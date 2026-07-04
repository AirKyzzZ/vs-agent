import { describe, expect, it } from 'vitest'
import { computeVerdict } from '../src/trust/verdict'

describe('computeVerdict', () => {
  it('is TRUSTED_AUTHORIZED only when Q1 TRUSTED and authorized true', () => {
    expect(computeVerdict({ status: 'ok', trustStatus: 'TRUSTED' }, true)).toBe('TRUSTED_AUTHORIZED')
  })
  it('is TRUSTED_NOT_AUTHORIZED when Q1 TRUSTED and authorized false', () => {
    expect(computeVerdict({ status: 'ok', trustStatus: 'TRUSTED' }, false)).toBe('TRUSTED_NOT_AUTHORIZED')
  })
  it('is UNTRUSTED when Q1 is UNTRUSTED or PARTIAL or not found, regardless of Q2/Q3', () => {
    expect(computeVerdict({ status: 'ok', trustStatus: 'UNTRUSTED' }, true)).toBe('UNTRUSTED')
    expect(computeVerdict({ status: 'ok', trustStatus: 'PARTIAL' }, true)).toBe('UNTRUSTED')
    expect(computeVerdict({ status: 'not_found' }, true)).toBe('UNTRUSTED')
  })
  it('is RESOLVER_UNAVAILABLE when Q1 unreachable or authorization unknown', () => {
    expect(computeVerdict({ status: 'unreachable' }, true)).toBe('RESOLVER_UNAVAILABLE')
    expect(computeVerdict({ status: 'ok', trustStatus: 'TRUSTED' }, null)).toBe('RESOLVER_UNAVAILABLE')
  })
})
