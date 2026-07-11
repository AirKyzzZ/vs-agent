import type { TrustEvidence, Verdict } from '../trust/types'
import type { OpenId4VcRegistryReference } from '../types'

export interface PartyResult {
  verdict: Verdict
  evidence: TrustEvidence
}

export interface ReceiptInput {
  sessionId: string
  verifierId: string
  vct: string | null
  disclosedClaims: Record<string, unknown>
  iss: string | null
  verifier: PartyResult
  issuer: PartyResult
  vtjscId: string
  registry?: OpenId4VcRegistryReference
  verifiedAt: string
}

export interface ReceiptRegistry {
  network?: string
  trustRegistry?: number
  schema?: number
  vtjscId: string
}

export interface ProofOfTrustReceipt {
  exchange: {
    protocol: 'OID4VP 1.0'
    vct: string | null
    verifiedAt: string
    sessionId: string
    verifierId: string
  }
  verifier: { did: string | null; verdict: Verdict; evidence: TrustEvidence }
  issuer: { did: string | null; iss: string | null; verdict: Verdict; evidence: TrustEvidence }
  credential: { vct: string | null; disclosedClaims: Record<string, unknown> }
  registry: ReceiptRegistry
}

export function buildReceipt(input: ReceiptInput): ProofOfTrustReceipt {
  return {
    exchange: {
      protocol: 'OID4VP 1.0',
      vct: input.vct,
      verifiedAt: input.verifiedAt,
      sessionId: input.sessionId,
      verifierId: input.verifierId,
    },
    verifier: {
      did: input.verifier.evidence.did,
      verdict: input.verifier.verdict,
      evidence: input.verifier.evidence,
    },
    issuer: {
      did: input.issuer.evidence.did,
      iss: input.iss,
      verdict: input.issuer.verdict,
      evidence: input.issuer.evidence,
    },
    credential: { vct: input.vct, disclosedClaims: input.disclosedClaims },
    registry: { ...input.registry, vtjscId: input.vtjscId },
  }
}
