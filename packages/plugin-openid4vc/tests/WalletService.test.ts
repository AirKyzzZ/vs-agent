import { describe, expect, it } from 'vitest'
import { evaluateRequestedVcts } from '../src/services/WalletService'

const VCT = 'https://issuer.test/vct/unfold-attestation'

describe('evaluateRequestedVcts', () => {
  it('matches when every credential entry requests exactly the expected vct', () => {
    expect(evaluateRequestedVcts([{ meta: { vct_values: [VCT] } }], VCT)).toEqual({ requestedVct: VCT, allMatch: true })
  })
  it('fails closed when any entry requests a different vct', () => {
    expect(evaluateRequestedVcts([{ meta: { vct_values: [VCT] } }, { meta: { vct_values: ['https://other'] } }], VCT).allMatch).toBe(false)
  })
  it('fails closed on missing vct_values, multi-value lists and empty queries', () => {
    expect(evaluateRequestedVcts([{ meta: {} }], VCT).allMatch).toBe(false)
    expect(evaluateRequestedVcts([{ meta: { vct_values: [VCT, 'https://other'] } }], VCT).allMatch).toBe(false)
    expect(evaluateRequestedVcts([], VCT).allMatch).toBe(false)
  })
})
