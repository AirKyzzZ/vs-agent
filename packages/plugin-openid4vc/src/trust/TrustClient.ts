import type { Q1Result, TrustVerdict } from './types'

import { computeVerdict } from './verdict'

export class TrustClient {
  public constructor(
    private readonly resolverUrl: string,
    private readonly fetchFn: typeof fetch = fetch,
  ) {}

  public async resolve(did: string): Promise<Q1Result> {
    try {
      const res = await this.fetchFn(this.resolveUrl(did), { headers: { accept: 'application/json' } })
      if (res.status === 404) return { status: 'not_found' }
      if (!res.ok) return { status: 'unreachable' }
      const body = (await res.json()) as Record<string, unknown>
      return {
        status: 'ok',
        trustStatus: body.trustStatus as 'TRUSTED' | 'PARTIAL' | 'UNTRUSTED' | undefined,
        production: body.production as boolean | undefined,
        evaluatedAt: body.evaluatedAt as string | undefined,
        evaluatedAtBlock: body.evaluatedAtBlock as number | undefined,
      }
    } catch {
      return { status: 'unreachable' }
    }
  }

  public async checkAuthorization(
    role: 'issuer' | 'verifier',
    did: string,
    vtjscId: string,
  ): Promise<boolean | null> {
    try {
      const res = await this.fetchFn(this.authorizationUrl(role, did, vtjscId), {
        headers: { accept: 'application/json' },
      })
      if (res.status === 404) return false
      if (!res.ok) return null
      const body = (await res.json()) as Record<string, unknown>
      return body.authorized === true
    } catch {
      return null
    }
  }

  public async verdictFor(
    role: 'issuer' | 'verifier',
    did: string | null,
    vtjscId: string | null,
  ): Promise<TrustVerdict> {
    if (!did) {
      return {
        verdict: 'UNTRUSTED',
        evidence: {
          did: null,
          trustStatus: null,
          authorized: null,
          vtjscId,
          queries: [],
          note: 'no DID could be extracted for this party',
        },
      }
    }
    const queries = [this.resolveUrl(did)]
    const q1 = await this.resolve(did)
    let authorized: boolean | null = null
    let note: string | undefined
    if (q1.status === 'ok' && q1.trustStatus === 'TRUSTED') {
      if (vtjscId) {
        queries.push(this.authorizationUrl(role, did, vtjscId))
        authorized = await this.checkAuthorization(role, did, vtjscId)
      } else {
        authorized = false
        note = 'no VTJSC mapping for the requested credential type'
      }
    }
    return {
      verdict: computeVerdict(q1, authorized),
      evidence: {
        did,
        trustStatus: q1.status === 'ok' ? (q1.trustStatus ?? null) : null,
        authorized,
        vtjscId,
        queries,
        note,
      },
    }
  }

  private resolveUrl(did: string): string {
    return `${this.resolverUrl}/resolve?did=${encodeURIComponent(did)}`
  }

  private authorizationUrl(role: 'issuer' | 'verifier', did: string, vtjscId: string): string {
    return `${this.resolverUrl}/${role}-authorization?did=${encodeURIComponent(did)}&vtjscId=${encodeURIComponent(vtjscId)}`
  }
}
