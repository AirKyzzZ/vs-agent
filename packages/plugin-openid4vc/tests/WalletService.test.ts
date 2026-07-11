import { describe, expect, it } from 'vitest'

import { extractRequestedVct } from '../src/services/WalletService'

const VCT = 'https://issuer.test/vct/org-attestation'

describe('extractRequestedVct', () => {
  it('returns the vct when every credential entry requests exactly that one vct', () => {
    expect(extractRequestedVct([{ meta: { vct_values: [VCT] } }])).toBe(VCT)
    expect(extractRequestedVct([{ meta: { vct_values: [VCT] } }, { meta: { vct_values: [VCT] } }])).toBe(VCT)
  })
  it('returns null when entries request different vcts', () => {
    expect(
      extractRequestedVct([{ meta: { vct_values: [VCT] } }, { meta: { vct_values: ['https://other'] } }]),
    ).toBeNull()
  })
  it('returns null on missing vct_values, multi-value lists and empty queries', () => {
    expect(extractRequestedVct([{ meta: {} }])).toBeNull()
    expect(extractRequestedVct([{ meta: { vct_values: [VCT, 'https://other'] } }])).toBeNull()
    expect(extractRequestedVct([])).toBeNull()
  })
})
