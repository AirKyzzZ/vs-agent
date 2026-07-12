import type { CertificateHandle } from './AgentSetup'
import type { StatusReference } from './StatusListService'
import type {
  OpenId4VcAgentModules,
  OpenId4VcCredentialConfiguration,
  OpenId4VcPluginOptions,
} from '../types'
import type { OpenId4VciCredentialRequestToCredentialMapper } from '@credo-ts/openid4vc'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { ClaimFormat, utils } from '@credo-ts/core'

import {
  buildVctTypeMetadata,
  findCredentialConfiguration,
  parseOfferClaims,
  resolveDisclosureFrame,
  resolveFormat,
} from '../config'

import { ensureP256CertificateWithDidSan, publishSigningKeyInDidDocument } from './AgentSetup'
import { StatusListService } from './StatusListService'

const DEFAULT_ISSUER_ID = 'issuer'
const DEFAULT_ISSUER_DISPLAY_NAME = 'Issuer'

export function resolveIssuerId(options: OpenId4VcPluginOptions): string {
  return options.issuerId ?? DEFAULT_ISSUER_ID
}

function toCredentialConfigurationDisplay(config: OpenId4VcCredentialConfiguration) {
  const display = config.display ?? {}
  return [
    {
      name: display.name ?? config.name,
      locale: display.locale ?? 'en',
      ...(display.backgroundColor ? { background_color: display.backgroundColor } : {}),
      ...(display.textColor ? { text_color: display.textColor } : {}),
      ...(display.logoUri ? { logo: { uri: display.logoUri } } : {}),
    },
  ]
}

function buildCredentialConfigurationsSupported(configs: OpenId4VcCredentialConfiguration[]) {
  return Object.fromEntries(
    configs.map(config => [
      config.id,
      {
        format: resolveFormat(config),
        vct: config.vct,
        cryptographic_binding_methods_supported: ['jwk'],
        credential_signing_alg_values_supported: ['ES256'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
        display: toCredentialConfigurationDisplay(config),
      },
    ]),
  )
}

export function buildSdJwtPayload(vct: string, claims: Record<string, string>, status?: StatusReference) {
  const origin = new URL(vct).origin
  return {
    vct,
    id: `${origin}/subjects/${utils.uuid()}`,
    ...claims,
    ...(status ? { status } : {}),
  }
}

let issuerCertificate: CertificateHandle | undefined
let statusListService: StatusListService | undefined

export function buildCredentialRequestToCredentialMapper(
  options: OpenId4VcPluginOptions,
): OpenId4VciCredentialRequestToCredentialMapper {
  return async ({ holderBinding, issuanceSession, credentialConfigurationId }) => {
    if (!issuerCertificate) throw new Error('issuer certificate not initialized')
    const config = findCredentialConfiguration(options.credentialConfigurations, credentialConfigurationId)
    if (!config) throw new Error(`unknown credential configuration '${credentialConfigurationId}'`)
    const x5c = issuerCertificate.chain
    const claims = issuanceSession.issuanceMetadata as Record<string, string>
    const credentials = await Promise.all(
      holderBinding.keys.map(async holderKey => ({
        payload: buildSdJwtPayload(
          config.vct,
          claims,
          statusListService ? await statusListService.allocate(issuanceSession.id) : undefined,
        ),
        holder:
          holderKey.method === 'did'
            ? { method: 'did' as const, didUrl: holderKey.didUrl }
            : { method: 'jwk' as const, jwk: holderKey.jwk },
        issuer: {
          method: 'x5c' as const,
          x5c,
          issuer: options.publicApiBaseUrl,
        },
        disclosureFrame: { _sd: resolveDisclosureFrame(config) },
        headerType: resolveFormat(config),
      })),
    )
    return { type: 'credentials', format: ClaimFormat.SdJwtDc, credentials }
  }
}

// SD-JWT VC issuer-key discovery: wallets require /.well-known/jwt-vc-issuer to validate the
// issuer signature even when the credential carries an x5c chain.
export function getIssuerSigningJwk(): Record<string, unknown> | null {
  return issuerCertificate
    ? (issuerCertificate.certificate.publicJwk.toJson() as Record<string, unknown>)
    : null
}

/** The signed status list token for `listId`, served at `<publicApiBaseUrl>/oid4vc/status-list/:id`. */
export function getStatusListToken(listId: string): string | undefined {
  return statusListService?.getToken(listId)
}

export class IssuerService {
  private initPromise?: Promise<void>

  public constructor(
    private readonly agent: VsAgent<OpenId4VcAgentModules>,
    private readonly options: OpenId4VcPluginOptions,
  ) {}

  private async initialize(): Promise<void> {
    const host = new URL(this.options.publicApiBaseUrl).hostname
    const displayName = this.options.issuerDisplayName ?? DEFAULT_ISSUER_DISPLAY_NAME
    issuerCertificate = await ensureP256CertificateWithDidSan(this.agent, {
      genericRecordId: 'oid4vc-issuer-certificate',
      commonName: displayName,
      sanUri: this.agent.did ?? this.options.publicApiBaseUrl,
      sanDns: host,
      useCertificateChain: this.options.certificateChain?.enabled,
    })
    const issuerId = resolveIssuerId(this.options)
    const credentialConfigurationsSupported = buildCredentialConfigurationsSupported(
      this.options.credentialConfigurations,
    )
    const issuerApi = this.issuerApi()
    const existing = await issuerApi.getIssuerByIssuerId(issuerId).catch(() => null)
    if (!existing) {
      await issuerApi.createIssuer({
        issuerId,
        display: [{ name: displayName, locale: 'en' }],
        credentialConfigurationsSupported,
      })
    } else {
      await issuerApi.updateIssuerMetadata({
        issuerId,
        display: existing.display,
        credentialConfigurationsSupported: {
          ...existing.credentialConfigurationsSupported,
          ...credentialConfigurationsSupported,
        },
      })
    }
    await publishSigningKeyInDidDocument(this.agent, issuerCertificate, ['assertionMethod'])

    if (this.options.revocation?.enabled) {
      statusListService = new StatusListService(
        this.agent,
        issuerCertificate,
        this.options.publicApiBaseUrl,
        this.options.revocation.size,
      )
      await statusListService.initialize()
    }
  }

  public ensureInitialized(): Promise<void> {
    this.initPromise ??= this.initialize().catch(error => {
      this.initPromise = undefined
      throw error
    })
    return this.initPromise
  }

  public async createOffer(
    credentialConfigurationId: string,
    rawClaims: unknown,
    opts?: { requireWalletAttestation?: boolean },
  ) {
    await this.ensureInitialized()
    const config = findCredentialConfiguration(
      this.options.credentialConfigurations,
      credentialConfigurationId,
    )
    if (!config) throw new Error(`unknown credential configuration '${credentialConfigurationId}'`)
    const claims = parseOfferClaims(config, rawClaims)
    const { credentialOffer, issuanceSession } = await this.issuerApi().createCredentialOffer({
      issuerId: resolveIssuerId(this.options),
      credentialConfigurationIds: [config.id],
      preAuthorizedCodeFlowConfig: {},
      issuanceMetadata: claims,
      ...(opts?.requireWalletAttestation
        ? { authorization: { requireWalletAttestation: true, requireDpop: false } }
        : {}),
    })
    return { credentialOffer, issuanceSessionId: issuanceSession.id }
  }

  public async getOfferState(id: string) {
    const session = await this.issuerApi().getIssuanceSessionById(id)
    return { state: session.state }
  }

  /**
   * Revoke every credential issued for an issuance session by flipping its Token Status List entry.
   * Requires `revocation.enabled`. Returns the affected indices; idempotent.
   */
  public async revoke(issuanceSessionId: string): Promise<number[]> {
    await this.ensureInitialized()
    if (!statusListService) throw new Error('revocation is not enabled for this issuer')
    return statusListService.revoke(issuanceSessionId)
  }

  /** SD-JWT VC Type Metadata for the credential configuration served at `<publicApiBaseUrl>/vct/<id>`. */
  public getVctMetadata(id: string): Record<string, unknown> | undefined {
    const config = this.options.credentialConfigurations.find(candidate => {
      try {
        return new URL(candidate.vct).pathname.split('/').pop() === id
      } catch {
        return false
      }
    })
    return config ? buildVctTypeMetadata(config) : undefined
  }

  private issuerApi() {
    const api = this.agent.modules.openId4Vc.issuer
    if (!api) throw new Error('openId4Vc issuer api not enabled on this agent')
    return api
  }
}
