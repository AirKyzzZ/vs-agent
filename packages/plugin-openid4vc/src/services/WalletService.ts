import type { TrustVerdict, Verdict } from '../trust/types'
import type { OpenId4VcPluginOptions } from '../types'
import type { SdJwtVcRecord } from '@credo-ts/core'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { Kms, X509Certificate } from '@credo-ts/core'

import { TrustClient } from '../trust/TrustClient'

import { didFromCertificateSan } from './AgentSetup'
import { GateStore } from './GateStore'

export class GateBlockedError extends Error {
  public constructor(
    public readonly verdict: Verdict,
    public readonly reason: string,
  ) {
    super(reason)
  }
}

export class ShareSubmissionError extends Error {}

export function evaluateRequestedVcts(
  credentials: unknown[],
  expectedVct: string,
): { requestedVct: string | null; allMatch: boolean } {
  if (credentials.length === 0) return { requestedVct: null, allMatch: false }
  const vcts = credentials.map(credential => {
    const meta = (credential as { meta?: { vct_values?: unknown } })?.meta
    const values = Array.isArray(meta?.vct_values) ? meta.vct_values : []
    return values.length === 1 && typeof values[0] === 'string' ? values[0] : null
  })
  return { requestedVct: vcts[0], allMatch: vcts.every(vct => vct === expectedVct) }
}

export class WalletService {
  private readonly gates = new GateStore()
  private readonly trustClient: TrustClient

  public constructor(
    private readonly agent: VsAgent,
    private readonly options: OpenId4VcPluginOptions,
  ) {
    this.trustClient = new TrustClient(options.resolverUrl)
  }

  public async acceptOffer(offerUri: string) {
    const holder = this.holderApi()
    const resolved = await holder.resolveCredentialOffer(offerUri)
    const token = await holder.requestToken({ resolvedCredentialOffer: resolved })
    const { credentials } = await holder.requestCredentials({
      resolvedCredentialOffer: resolved,
      accessToken: token.accessToken,
      cNonce: token.cNonce,
      dpop: token.dpop,
      credentialBindingResolver: async () => {
        const key = await this.agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
        const publicJwk = Kms.PublicJwk.fromPublicJwk(key.publicJwk)
        publicJwk.keyId = key.keyId
        return { method: 'jwk' as const, keys: [publicJwk] }
      },
    })
    const record = credentials[0].record as SdJwtVcRecord
    await this.agent.sdJwtVc.store({ record })
    return this.summarize(record)
  }

  public async listCredentials() {
    const records = await this.agent.sdJwtVc.getAll()
    return { credentials: records.map(record => this.summarize(record)) }
  }

  public async clearCredentials() {
    const records = await this.agent.sdJwtVc.getAll()
    for (const record of records) await this.agent.sdJwtVc.deleteById(record.id)
  }

  public async resolveRequest(authorizationRequest: string) {
    const holder = this.holderApi()
    const resolved = await holder.resolveOpenId4VpAuthorizationRequest(authorizationRequest)
    const verifierDid = this.extractVerifierDid(resolved)
    const credentials = resolved.authorizationRequestPayload.dcql_query?.credentials ?? []
    const { requestedVct, allMatch } = evaluateRequestedVcts(credentials, this.options.vct)
    const vtjscId = allMatch ? this.options.vtjscId : null
    const trust: TrustVerdict = await this.trustClient.verdictFor('verifier', verifierDid, vtjscId)
    const gateId = this.gates.create({ ...trust, resolved })
    return {
      gateId,
      verdict: trust.verdict,
      evidence: trust.evidence,
      request: {
        clientId: resolved.verifier.effectiveClientId,
        clientIdPrefix: resolved.verifier.clientIdPrefix,
        verifierDid,
        requestedVct,
        requestedClaims: this.extractRequestedClaims(resolved),
      },
    }
  }

  public async share(gateId: string) {
    const gate = this.gates.get(gateId)
    if (!gate) throw new GateBlockedError('UNTRUSTED', 'unknown or expired gate')
    if (gate.verdict !== 'TRUSTED_AUTHORIZED') {
      throw new GateBlockedError(
        gate.verdict,
        'verifier is not a TRUSTED, authorized VERIFIER participant on the Verana registry',
      )
    }
    this.gates.consume(gateId)
    const holder = this.holderApi()
    if (!gate.resolved.dcql) throw new Error('resolved authorization request did not contain a dcql query')
    const credentials = holder.selectCredentialsForDcqlRequest(gate.resolved.dcql.queryResult)
    const result = await holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: gate.resolved.authorizationRequestPayload,
      dcql: { credentials },
    })
    if (!result.ok) {
      throw new ShareSubmissionError(
        `presentation submission failed with status ${result.serverResponse?.status}`,
      )
    }
    return { shared: true as const, status: result.serverResponse?.status ?? 200 }
  }

  private extractVerifierDid(resolved: { signedAuthorizationRequest?: { signer: unknown } }): string | null {
    const signer = resolved.signedAuthorizationRequest?.signer as
      | { method?: string; x5c?: string[] }
      | undefined
    if (signer?.method !== 'x5c' || !signer.x5c?.length) return null
    try {
      return didFromCertificateSan(X509Certificate.fromEncodedCertificate(signer.x5c[0]))
    } catch {
      return null
    }
  }

  private extractRequestedClaims(resolved: {
    authorizationRequestPayload: { dcql_query?: { credentials?: unknown[] } }
  }): string[] {
    const credentials = resolved.authorizationRequestPayload.dcql_query?.credentials ?? []
    return credentials.flatMap(credential => {
      const claims = (credential as { claims?: unknown[] })?.claims ?? []
      return claims.map(claim => {
        const path = (claim as { path?: unknown }).path
        return Array.isArray(path) ? path.join('.') : String(path)
      })
    })
  }

  private summarize(record: SdJwtVcRecord) {
    const { prettyClaims } = record.firstCredential
    return { id: record.id, vct: prettyClaims.vct as string, claims: prettyClaims }
  }

  private holderApi() {
    const api = (this.agent.modules as Record<string, any>).openId4Vc?.holder
    if (!api) throw new Error('openId4Vc holder api not available')
    return api
  }
}
