import type { CertificateHandle } from './AgentSetup'
import type { OpenId4VcPluginOptions } from '../types'
import type { OpenId4VciCredentialRequestToCredentialMapper } from '@credo-ts/openid4vc'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { ClaimFormat, VerificationMethod, utils } from '@credo-ts/core'

import { ensureP256CertificateWithDidSan } from './AgentSetup'

export const ISSUER_ID = 'unfold'
export const CREDENTIAL_CONFIGURATION_ID = 'unfold-attestation'
export const DISCLOSURE_FRAME = { _sd: ['organization', 'role'] }

export function parseOfferClaims(body: unknown): { organization: string; role: string } {
  const candidate = body as { organization?: unknown; role?: unknown } | null | undefined
  const organization = candidate?.organization
  const role = candidate?.role
  if (typeof organization !== 'string' || !organization.trim() || organization.length > 200) {
    throw new Error('organization must be a non-empty string of at most 200 characters')
  }
  if (typeof role !== 'string' || !role.trim() || role.length > 200) {
    throw new Error('role must be a non-empty string of at most 200 characters')
  }
  return { organization, role }
}

export function buildSdJwtPayload(vct: string, claims: { organization: string; role: string }) {
  const origin = new URL(vct).origin
  return {
    vct,
    id: `${origin}/subjects/${utils.uuid()}`,
    organization: claims.organization,
    role: claims.role,
  }
}

let issuerCertificate: CertificateHandle | undefined

export function buildCredentialRequestToCredentialMapper(
  options: OpenId4VcPluginOptions,
): OpenId4VciCredentialRequestToCredentialMapper {
  return ({ holderBinding, issuanceSession }) => {
    if (!issuerCertificate) throw new Error('issuer certificate not initialized')
    const certificate = issuerCertificate.certificate
    const claims = issuanceSession.issuanceMetadata as { organization: string; role: string }
    return {
      type: 'credentials',
      format: ClaimFormat.SdJwtDc,
      credentials: holderBinding.keys.map(holderKey => ({
        payload: buildSdJwtPayload(options.vct, claims),
        holder:
          holderKey.method === 'did'
            ? { method: 'did' as const, didUrl: holderKey.didUrl }
            : { method: 'jwk' as const, jwk: holderKey.jwk },
        issuer: {
          method: 'x5c' as const,
          x5c: [certificate],
          issuer: options.publicApiBaseUrl,
        },
        disclosureFrame: DISCLOSURE_FRAME,
      })),
    }
  }
}

export class IssuerService {
  private initPromise?: Promise<void>

  public constructor(
    private readonly agent: VsAgent,
    private readonly options: OpenId4VcPluginOptions,
  ) {}

  private async initialize(): Promise<void> {
    const host = new URL(this.options.publicApiBaseUrl).hostname
    issuerCertificate = await ensureP256CertificateWithDidSan(this.agent, {
      genericRecordId: 'oid4vc-issuer-certificate',
      commonName: 'Unfold Ecosystem Authority',
      sanUri: this.agent.did ?? this.options.publicApiBaseUrl,
      sanDns: host,
    })
    const issuerApi = this.issuerApi()
    const existing = await issuerApi.getIssuerByIssuerId(ISSUER_ID).catch(() => null)
    if (!existing) {
      await issuerApi.createIssuer({
        issuerId: ISSUER_ID,
        display: [{ name: 'Unfold Ecosystem Authority', locale: 'en' }],
        credentialConfigurationsSupported: {
          [CREDENTIAL_CONFIGURATION_ID]: {
            format: 'dc+sd-jwt',
            vct: this.options.vct,
            cryptographic_binding_methods_supported: ['jwk'],
            credential_signing_alg_values_supported: ['ES256'],
            proof_types_supported: { jwt: { proof_signing_alg_values_supported: ['ES256'] } },
          },
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

  public async createOffer(claims: { organization: string; role: string }) {
    await this.ensureInitialized()
    const { credentialOffer, issuanceSession } = await this.issuerApi().createCredentialOffer({
      issuerId: ISSUER_ID,
      credentialConfigurationIds: [CREDENTIAL_CONFIGURATION_ID],
      preAuthorizedCodeFlowConfig: {},
      issuanceMetadata: claims,
    })
    return { credentialOffer, issuanceSessionId: issuanceSession.id }
  }

  public async getOfferState(id: string) {
    const session = await this.issuerApi().getIssuanceSessionById(id)
    return { state: session.state }
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
    const api = (this.agent.modules as Record<string, any>).openId4Vc?.issuer
    if (!api) throw new Error('openId4Vc issuer api not enabled on this agent')
    return api
  }
}
