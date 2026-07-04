import type { TrustEvidence, Verdict } from '../trust/types'

export interface PartyResult {
  verdict: Verdict
  evidence: TrustEvidence
}

export interface ReceiptInput {
  sessionId: string
  tenant: 'trusted' | 'rogue'
  vct: string | null
  disclosedClaims: Record<string, unknown>
  iss: string | null
  verifier: PartyResult
  issuer: PartyResult
  vtjscId: string
  verifiedAt: string
}

export interface ProofOfTrustReceipt {
  exchange: {
    protocol: 'OID4VP 1.0'
    vct: string | null
    verifiedAt: string
    sessionId: string
    tenant: 'trusted' | 'rogue'
  }
  verifier: { did: string | null; verdict: Verdict; evidence: TrustEvidence }
  issuer: { did: string | null; iss: string | null; verdict: Verdict; evidence: TrustEvidence }
  credential: { vct: string | null; disclosedClaims: Record<string, unknown> }
  registry: { network: 'vna-testnet-1'; trustRegistry: 184; schema: 249; vtjscId: string }
}

export function buildReceipt(input: ReceiptInput): ProofOfTrustReceipt {
  return {
    exchange: {
      protocol: 'OID4VP 1.0',
      vct: input.vct,
      verifiedAt: input.verifiedAt,
      sessionId: input.sessionId,
      tenant: input.tenant,
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
    registry: { network: 'vna-testnet-1', trustRegistry: 184, schema: 249, vtjscId: input.vtjscId },
  }
}
