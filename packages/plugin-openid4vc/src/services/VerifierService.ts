import type { OpenId4VcPluginOptions } from '../types'
import type { X509Certificate } from '@credo-ts/core'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { TrustClient } from '../trust/TrustClient'

import { type CertificateHandle, ensureP256CertificateWithDidSan } from './AgentSetup'
import { buildReceipt, type ProofOfTrustReceipt } from './receipt'

const TENANTS = ['trusted', 'rogue'] as const
export type Tenant = (typeof TENANTS)[number]

export class UnknownSessionError extends Error {}

interface DecodedSdJwtPresentation {
  payload?: { iss?: unknown }
  prettyClaims?: Record<string, unknown>
  issuer?: { method: 'x5c'; x5c: X509Certificate[] } | { method: 'did'; didUrl: string }
}

export class VerifierService {
  private initPromise?: Promise<void>
  private readonly certificates = new Map<Tenant, CertificateHandle>()
  private readonly sessionTenants = new Map<string, Tenant>()
  private readonly trustClient: TrustClient

  public constructor(
    private readonly agent: VsAgent,
    private readonly options: OpenId4VcPluginOptions,
  ) {
    this.trustClient = new TrustClient(options.resolverUrl)
  }

  private async initialize(): Promise<void> {
    const host = new URL(this.options.publicApiBaseUrl).hostname
    const verifierApi = this.verifierApi()
    for (const tenant of TENANTS) {
      const sanUri =
        tenant === 'trusted'
          ? (this.agent.did ?? this.options.publicApiBaseUrl)
          : this.options.rogueVerifierDid
      this.certificates.set(
        tenant,
        await ensureP256CertificateWithDidSan(this.agent, {
          genericRecordId: `oid4vc-verifier-certificate-${tenant}`,
          commonName: tenant === 'trusted' ? 'Unfold Verifier' : 'Rogue Verifier',
          sanUri,
          sanDns: host,
        }),
      )
      const existing = await verifierApi.getVerifierByVerifierId(tenant).catch(() => null)
      if (!existing) {
        await verifierApi.createVerifier({
          verifierId: tenant,
          clientMetadata: { client_name: tenant === 'trusted' ? 'Unfold Verifier' : 'Rogue Verifier' },
        })
      }
    }
  }

  public ensureInitialized(): Promise<void> {
    this.initPromise ??= this.initialize().catch(error => {
      this.initPromise = undefined
      throw error
    })
    return this.initPromise
  }

  public async createRequest(tenant: Tenant): Promise<{ authorizationRequest: string; sessionId: string }> {
    await this.ensureInitialized()
    const certificate = this.certificates.get(tenant)
    if (!certificate) throw new Error(`no certificate initialized for tenant '${tenant}'`)
    const { authorizationRequest, verificationSession } = await this.verifierApi().createAuthorizationRequest(
      {
        verifierId: tenant,
        requestSigner: { method: 'x5c', x5c: [certificate.certificate], clientIdPrefix: 'x509_hash' },
        responseMode: 'direct_post.jwt',
        dcql: {
          query: {
            credentials: [
              {
                id: 'unfold-attestation',
                format: 'dc+sd-jwt',
                meta: { vct_values: [this.options.vct] },
                claims: [{ path: ['organization'] }, { path: ['role'] }],
              },
            ],
          },
        },
      },
    )
    this.sessionTenants.set(verificationSession.id, tenant)
    return { authorizationRequest, sessionId: verificationSession.id }
  }

  public async getSession(sessionId: string): Promise<{ state: string; receipt?: ProofOfTrustReceipt }> {
    const tenant = this.sessionTenants.get(sessionId)
    if (!tenant) throw new UnknownSessionError(`unknown verification session '${sessionId}'`)

    const session = await this.verifierApi().getVerificationSessionById(sessionId)
    if (session.state !== 'ResponseVerified') return { state: session.state }

    const verified = await this.verifierApi().getVerifiedAuthorizationResponse(sessionId)
    const presentations = verified.dcql?.presentations as
      | Record<string, DecodedSdJwtPresentation[]>
      | undefined
    const presentation = presentations?.['unfold-attestation']?.[0]

    const claims = presentation?.prettyClaims
    const vct = typeof claims?.vct === 'string' ? claims.vct : null
    const disclosedClaims: Record<string, unknown> = {}
    if (claims && 'organization' in claims) disclosedClaims.organization = claims.organization
    if (claims && 'role' in claims) disclosedClaims.role = claims.role

    const iss = typeof presentation?.payload?.iss === 'string' ? presentation.payload.iss : null
    const issuerDid = iss?.startsWith('did:') ? iss : null

    const verifierDid = tenant === 'trusted' ? (this.agent.did ?? null) : this.options.rogueVerifierDid

    const [verifierTrust, issuerTrust] = await Promise.all([
      this.trustClient.verdictFor('verifier', verifierDid, this.options.vtjscId),
      this.trustClient.verdictFor('issuer', issuerDid, this.options.vtjscId),
    ])

    return {
      state: session.state,
      receipt: buildReceipt({
        sessionId,
        tenant,
        vct,
        disclosedClaims,
        iss,
        verifier: verifierTrust,
        issuer: issuerTrust,
        vtjscId: this.options.vtjscId,
        verifiedAt: new Date().toISOString(),
      }),
    }
  }

  private verifierApi() {
    const api = (this.agent.modules as Record<string, any>).openId4Vc?.verifier
    if (!api) throw new Error('openId4Vc verifier api not enabled on this agent')
    return api
  }
}
