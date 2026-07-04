import { describe, expect, it } from 'vitest'

import { buildSdJwtPayload, DISCLOSURE_FRAME, parseOfferClaims } from '../src/services/IssuerService'

describe('sd-jwt payload construction', () => {
  it('builds vct, subject id and claims', () => {
    const payload = buildSdJwtPayload('https://vct.example/unfold-attestation', {
      organization: 'ACME',
      role: 'employee',
    })
    expect(payload.vct).toBe('https://vct.example/unfold-attestation')
    expect(payload.organization).toBe('ACME')
    expect(payload.role).toBe('employee')
    expect(String(payload.id)).toMatch(/^https:\/\/vct\.example\/subjects\//)
  })

  it('selectively discloses organization and role only', () => {
    expect(DISCLOSURE_FRAME).toEqual({ _sd: ['organization', 'role'] })
  })
})

describe('parseOfferClaims', () => {
  it('accepts plain string claims', () => {
    expect(parseOfferClaims({ organization: 'ACME', role: 'employee' })).toEqual({ organization: 'ACME', role: 'employee' })
  })
  it('rejects non-string values', () => {
    expect(() => parseOfferClaims({ organization: { a: 1 }, role: 'r' })).toThrow()
    expect(() => parseOfferClaims({ organization: 'o', role: ['r'] })).toThrow()
  })
  it('rejects empty and oversized values', () => {
    expect(() => parseOfferClaims({ organization: '  ', role: 'r' })).toThrow()
    expect(() => parseOfferClaims({ organization: 'o'.repeat(201), role: 'r' })).toThrow()
  })
})
