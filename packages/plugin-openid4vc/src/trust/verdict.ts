import type { Q1Result, Verdict } from './types'

export function computeVerdict(q1: Q1Result, authorized: boolean | null): Verdict {
  if (q1.status === 'unreachable') return 'RESOLVER_UNAVAILABLE'
  if (q1.status === 'not_found' || q1.trustStatus !== 'TRUSTED') return 'UNTRUSTED'
  if (authorized === null) return 'RESOLVER_UNAVAILABLE'
  return authorized ? 'TRUSTED_AUTHORIZED' : 'TRUSTED_NOT_AUTHORIZED'
}
