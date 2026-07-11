import type { CertificateHandle } from './AgentSetup'
import type {
  OpenId4VcAgentModules,
  OpenId4VcCredentialConfiguration,
  OpenId4VcPluginOptions,
} from '../types'
import type { OpenId4VciCredentialRequestToCredentialMapper } from '@credo-ts/openid4vc'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { ClaimFormat, VerificationMethod, utils } from '@credo-ts/core'

import {
  findCredentialConfiguration,
  parseOfferClaims,
  resolveDisclosureFrame,
  resolveFormat,
} from '../config'

import { ensureP256CertificateWithDidSan } from './AgentSetup'

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

export function buildSdJwtPayload(vct: string, claims: Record<string, string>) {
  const origin = new URL(vct).origin
  return {
    vct,
    id: `${origin}/subjects/${utils.uuid()}`,
    ...claims,
  }
}

let issuerCertificate: CertificateHandle | undefined

export function buildCredentialRequestToCredentialMapper(
  options: OpenId4VcPluginOptions,
): OpenId4VciCredentialRequestToCredentialMapper {
  return ({ holderBinding, issuanceSession, credentialConfigurationId }) => {
    if (!issuerCertificate) throw new Error('issuer certificate not initialized')
    const config = findCredentialConfiguration(options.credentialConfigurations, credentialConfigurationId)
    if (!config) throw new Error(`unknown credential configuration '${credentialConfigurationId}'`)
    const certificate = issuerCertificate.certificate
    const claims = issuanceSession.issuanceMetadata as Record<string, string>
    return {
      type: 'credentials',
      format: ClaimFormat.SdJwtDc,
      credentials: holderBinding.keys.map(holderKey => ({
        payload: buildSdJwtPayload(config.vct, claims),
        holder:
          holderKey.method === 'did'
            ? { method: 'did' as const, didUrl: holderKey.didUrl }
            : { method: 'jwk' as const, jwk: holderKey.jwk },
        issuer: {
          method: 'x5c' as const,
          x5c: [certificate],
          issuer: options.publicApiBaseUrl,
        },
        disclosureFrame: { _sd: resolveDisclosureFrame(config) },
        headerType: resolveFormat(config),
      })),
    }
  }
}

// SD-JWT VC issuer-key discovery: wallets require /.well-known/jwt-vc-issuer to validate the
// issuer signature even when the credential carries an x5c chain.
export function getIssuerSigningJwk(): Record<string, unknown> | null {
  return issuerCertificate
    ? (issuerCertificate.certificate.publicJwk.toJson() as Record<string, unknown>)
    : null
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
    await this.publishSigningKeyInDidDocument(issuerCertificate)
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

  /** VCT type metadata for the credential configuration served at `<publicApiBaseUrl>/vct/<id>`. */
  public getVctMetadata(id: string): { vct: string; name: string; description?: string } | undefined {
    const config = this.options.credentialConfigurations.find(candidate => {
      try {
        return new URL(candidate.vct).pathname.split('/').pop() === id
      } catch {
        return false
      }
    })
    if (!config) return undefined
    return {
      vct: config.vct,
      name: config.name,
      ...(config.description ? { description: config.description } : {}),
    }
  }

  private async publishSigningKeyInDidDocument(certificate: CertificateHandle): Promise<void> {
    if (!this.agent.did) return
    try {
      const [didRecord] = await this.agent.dids.getCreatedDids({ did: this.agent.did })
      const didDocument = didRecord?.didDocument
      if (!didDocument) return
      const methodId = `${this.agent.did}#oid4vc-es256`
      if (didDocument.verificationMethod?.some(vm => vm.id === methodId)) return
      didDocument.verificationMethod = [
        ...(didDocument.verificationMethod ?? []),
        new VerificationMethod({
          id: methodId,
          type: 'JsonWebKey2020',
          controller: this.agent.did,
          publicKeyJwk: certificate.certificate.publicJwk.toJson(),
        }),
      ]
      didDocument.assertionMethod = [...(didDocument.assertionMethod ?? []), methodId]
      await this.agent.dids.update({ did: this.agent.did, didDocument })
    } catch (error) {
      this.agent.config.logger.warn(`could not publish ES256 key in DID document: ${error}`)
    }
  }

  private issuerApi() {
    const api = this.agent.modules.openId4Vc.issuer
    if (!api) throw new Error('openId4Vc issuer api not enabled on this agent')
    return api
  }
}
