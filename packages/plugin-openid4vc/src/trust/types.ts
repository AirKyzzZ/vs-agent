export type Verdict = 'TRUSTED_AUTHORIZED' | 'TRUSTED_NOT_AUTHORIZED' | 'UNTRUSTED' | 'RESOLVER_UNAVAILABLE'

export type Q1Result =
  | { status: 'ok'; trustStatus?: 'TRUSTED' | 'PARTIAL' | 'UNTRUSTED'; production?: boolean; evaluatedAt?: string; evaluatedAtBlock?: number }
  | { status: 'not_found' }
  | { status: 'unreachable' }

export interface TrustEvidence {
  did: string | null
  trustStatus: 'TRUSTED' | 'PARTIAL' | 'UNTRUSTED' | null
  authorized: boolean | null
  vtjscId: string | null
  queries: string[]
  note?: string
}

export interface TrustVerdict {
  verdict: Verdict
  evidence: TrustEvidence
}
