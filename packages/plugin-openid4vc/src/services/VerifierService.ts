import type {
  OpenId4VcAgentModules,
  OpenId4VcCredentialConfiguration,
  OpenId4VcPluginOptions,
} from '../types'
import type { X509Certificate } from '@credo-ts/core'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { findCredentialConfiguration, resolveFormat } from '../config'
import { TrustClient } from '../trust/TrustClient'
import { blockingBindingVerdict, verifyKeyBoundToDid } from '../trust/keyBinding'

import {
  type CertificateHandle,
  didFromCertificateSan,
  ensureP256CertificateWithDidSan,
  publishSigningKeyInDidDocument,
} from './AgentSetup'
import { buildReceipt, type ProofOfTrustReceipt } from './receipt'

const DEFAULT_VERIFIER_ID = 'verifier'
const DEFAULT_VERIFIER_DISPLAY_NAME = 'Verifier'

export class UnknownSessionError extends Error {}

interface DecodedSdJwtPresentation {
  payload?: { iss?: unknown }
  prettyClaims?: Record<string, unknown>
  issuer?: { method: 'x5c'; x5c: X509Certificate[] } | { method: 'did'; didUrl: string }
}

export class VerifierService {
  private initPromise?: Promise<void>
  private certificate?: CertificateHandle
  private readonly sessionConfigs = new Map<string, string>()
  private readonly trustClient: TrustClient

  public constructor(
    private readonly agent: VsAgent<OpenId4VcAgentModules>,
    private readonly options: OpenId4VcPluginOptions,
  ) {
    this.trustClient = new TrustClient(options.resolverUrl)
  }

  private get verifierId(): string {
    return this.options.verifierId ?? DEFAULT_VERIFIER_ID
  }

  private get displayName(): string {
    return this.options.verifierDisplayName ?? DEFAULT_VERIFIER_DISPLAY_NAME
  }

  private async initialize(): Promise<void> {
    const host = new URL(this.options.publicApiBaseUrl).hostname
    this.certificate = await ensureP256CertificateWithDidSan(this.agent, {
      genericRecordId: 'oid4vc-verifier-certificate',
      commonName: this.displayName,
      sanUri: this.agent.did ?? this.options.publicApiBaseUrl,
      sanDns: host,
      useCertificateChain: this.options.certificateChain?.enabled,
    })
    const verifierApi = this.verifierApi()
    const existing = await verifierApi.getVerifierByVerifierId(this.verifierId).catch(() => null)
    if (!existing) {
      await verifierApi.createVerifier({
        verifierId: this.verifierId,
        clientMetadata: { client_name: this.displayName },
      })
    }
    await publishSigningKeyInDidDocument(this.agent, this.certificate, ['authentication', 'assertionMethod'])
  }

  public ensureInitialized(): Promise<void> {
    this.initPromise ??= this.initialize().catch(error => {
      this.initPromise = undefined
      throw error
    })
    return this.initPromise
  }

  private credentialConfiguration(credentialConfigurationId?: string): OpenId4VcCredentialConfiguration {
    const config = credentialConfigurationId
      ? findCredentialConfiguration(this.options.credentialConfigurations, credentialConfigurationId)
      : this.options.credentialConfigurations[0]
    if (!config) throw new Error(`unknown credential configuration '${credentialConfigurationId}'`)
    return config
  }

  public async createRequest(
    credentialConfigurationId?: string,
  ): Promise<{ authorizationRequest: string; sessionId: string }> {
    await this.ensureInitialized()
    if (!this.certificate) throw new Error('verifier certificate not initialized')
    const config = this.credentialConfiguration(credentialConfigurationId)
    const { authorizationRequest, verificationSession } = await this.verifierApi().createAuthorizationRequest(
      {
        verifierId: this.verifierId,
        requestSigner: { method: 'x5c', x5c: this.certificate.chain, clientIdPrefix: 'x509_hash' },
        responseMode: 'direct_post.jwt',
        dcql: {
          query: {
            credentials: [
              {
                id: config.id,
                format: resolveFormat(config),
                meta: { vct_values: [config.vct] },
                claims: config.claims.map(name => ({ path: [name] })),
              },
            ],
          },
        },
      },
    )
    this.sessionConfigs.set(verificationSession.id, config.id)
    return { authorizationRequest, sessionId: verificationSession.id }
  }

  public async getSession(sessionId: string): Promise<{ state: string; receipt?: ProofOfTrustReceipt }> {
    const configId = this.sessionConfigs.get(sessionId)
    if (!configId) throw new UnknownSessionError(`unknown verification session '${sessionId}'`)
    const config = this.credentialConfiguration(configId)

    const session = await this.verifierApi().getVerificationSessionById(sessionId)
    if (session.state !== 'ResponseVerified') return { state: session.state }

    const verified = await this.verifierApi().getVerifiedAuthorizationResponse(sessionId)
    const presentations = verified.dcql?.presentations as
      | Record<string, DecodedSdJwtPresentation[]>
      | undefined
    const presentation = presentations?.[config.id]?.[0]

    const claims = presentation?.prettyClaims
    const vct = typeof claims?.vct === 'string' ? claims.vct : null
    const disclosedClaims: Record<string, unknown> = {}
    for (const name of config.claims) {
      if (claims && name in claims) disclosedClaims[name] = claims[name]
    }

    // Reaching ResponseVerified means Credo's fail-closed status check already passed, so a
    // credential that carried a status reference is confirmed not-revoked. A revoked credential
    // fails verification upstream and never produces a receipt.
    const carriesStatus = !!claims && typeof claims.status === 'object' && claims.status !== null

    const iss = typeof presentation?.payload?.iss === 'string' ? presentation.payload.iss : null
    const issuerCertificate = presentation?.issuer?.method === 'x5c' ? presentation.issuer.x5c[0] : undefined
    const issuerDid = didFromCertificateSan(issuerCertificate)
    const verifierDid = this.agent.did ?? null

    // Authenticate the DID -> signing-key binding before the registry lookup: the credential's
    // actual signing key must be an assertionMethod of the asserted issuer DID's document. A
    // self-signed cert asserting someone else's DID in its SAN fails here and never reaches Verana.
    const issuerKey = issuerCertificate
      ? (issuerCertificate.publicJwk.toJson() as Record<string, unknown>)
      : undefined
    const issuerBinding = await verifyKeyBoundToDid(this.agent, issuerDid, issuerKey, ['assertionMethod'])

    const [verifierTrust, issuerTrust] = await Promise.all([
      this.trustClient.verdictFor('verifier', verifierDid, config.vtjscId),
      issuerBinding === 'bound'
        ? this.trustClient.verdictFor('issuer', issuerDid, config.vtjscId)
        : Promise.resolve(blockingBindingVerdict(issuerDid, config.vtjscId, issuerBinding)),
    ])

    return {
      state: session.state,
      receipt: buildReceipt({
        sessionId,
        verifierId: this.verifierId,
        vct,
        disclosedClaims,
        iss,
        verifier: verifierTrust,
        issuer: issuerTrust,
        vtjscId: config.vtjscId,
        registry: this.options.registry,
        verifiedAt: new Date().toISOString(),
        ...(carriesStatus ? { credentialStatus: 'valid' as const } : {}),
      }),
    }
  }

  /** Public JWK of this verifier's request-signing key (published into its DID document). */
  public getSigningJwk(): Record<string, unknown> | null {
    return this.certificate
      ? (this.certificate.certificate.publicJwk.toJson() as Record<string, unknown>)
      : null
  }

  private verifierApi() {
    const api = this.agent.modules.openId4Vc.verifier
    if (!api) throw new Error('openId4Vc verifier api not enabled on this agent')
    return api
  }
}
