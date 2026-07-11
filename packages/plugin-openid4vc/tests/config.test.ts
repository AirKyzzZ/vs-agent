import type { OpenId4VcCredentialConfiguration } from '../src/types'

import { describe, expect, it } from 'vitest'

import {
  buildVctTypeMetadata,
  findConfigurationByVct,
  findCredentialConfiguration,
  parseOfferClaims,
  resolveDisclosureFrame,
  resolveFormat,
  validateCredentialConfigurations,
} from '../src/config'

const base: OpenId4VcCredentialConfiguration = {
  id: 'org-attestation',
  vct: 'https://issuer.example/vct/org-attestation',
  name: 'Org Attestation',
  vtjscId: 'https://issuer.example/vt/schemas-org-jsc.json',
  claims: ['organization', 'role'],
}

describe('resolveFormat', () => {
  it('defaults to dc+sd-jwt (HAIP)', () => {
    expect(resolveFormat(base)).toBe('dc+sd-jwt')
  })
  it('honors an explicit format', () => {
    expect(resolveFormat({ ...base, format: 'vc+sd-jwt' })).toBe('vc+sd-jwt')
  })
})

describe('resolveDisclosureFrame', () => {
  it('defaults to the full claim list', () => {
    expect(resolveDisclosureFrame(base)).toEqual(['organization', 'role'])
  })
  it('honors an explicit disclosure frame', () => {
    expect(resolveDisclosureFrame({ ...base, disclosureFrame: ['role'] })).toEqual(['role'])
  })
})

describe('lookups', () => {
  const configs = [base, { ...base, id: 'other', vct: 'https://issuer.example/vct/other' }]
  it('finds by id and by vct', () => {
    expect(findCredentialConfiguration(configs, 'other')?.id).toBe('other')
    expect(findConfigurationByVct(configs, base.vct)?.id).toBe('org-attestation')
  })
  it('returns undefined for unknown id/vct', () => {
    expect(findCredentialConfiguration(configs, 'nope')).toBeUndefined()
    expect(findConfigurationByVct(configs, 'https://nope')).toBeUndefined()
  })
})

describe('validateCredentialConfigurations', () => {
  it('accepts a valid list', () => {
    expect(() => validateCredentialConfigurations([base])).not.toThrow()
  })
  it('rejects an empty list', () => {
    expect(() => validateCredentialConfigurations([])).toThrow(/non-empty/)
  })
  it('rejects duplicate ids', () => {
    expect(() => validateCredentialConfigurations([base, base])).toThrow(/duplicate/)
  })
  it('rejects a missing name', () => {
    expect(() => validateCredentialConfigurations([{ ...base, name: '' }])).toThrow(/name/)
  })
  it('rejects a non-URL vct or vtjscId', () => {
    expect(() => validateCredentialConfigurations([{ ...base, vct: 'not a url' }])).toThrow(/vct/)
    expect(() => validateCredentialConfigurations([{ ...base, vtjscId: 'nope' }])).toThrow(/vtjscId/)
  })
  it('rejects empty claims', () => {
    expect(() => validateCredentialConfigurations([{ ...base, claims: [] }])).toThrow(/claims/)
  })
  it('rejects a disclosureFrame that is not a subset of claims', () => {
    expect(() => validateCredentialConfigurations([{ ...base, disclosureFrame: ['ghost'] }])).toThrow(
      /subset/,
    )
  })
  it('rejects an invalid format and non-string claims', () => {
    expect(() => validateCredentialConfigurations([{ ...base, format: 'ldp_vc' as never }])).toThrow(/format/)
    expect(() => validateCredentialConfigurations([{ ...base, claims: ['organization', ''] }])).toThrow(
      /claim/,
    )
  })
  it('allows the same vct under two different formats but rejects the same vct+format twice', () => {
    expect(() =>
      validateCredentialConfigurations([
        { ...base, id: 'a', format: 'dc+sd-jwt' },
        { ...base, id: 'b', format: 'vc+sd-jwt' },
      ]),
    ).not.toThrow()
    expect(() =>
      validateCredentialConfigurations([
        { ...base, id: 'a', format: 'dc+sd-jwt' },
        { ...base, id: 'b', format: 'dc+sd-jwt' },
      ]),
    ).toThrow(/duplicate credential configuration for vct/)
  })
})

describe('buildVctTypeMetadata', () => {
  it('builds a display block with rendering and per-claim descriptors', () => {
    const metadata = buildVctTypeMetadata({
      ...base,
      description: 'An org attestation',
      disclosureFrame: ['role'],
      display: { locale: 'en', backgroundColor: '#763EF0', textColor: '#FFFFFF' },
    }) as {
      vct: string
      display: { name: string; rendering: { simple: Record<string, unknown> } }[]
      claims: { path: string[]; sd: string }[]
    }
    expect(metadata.vct).toBe(base.vct)
    expect(metadata.display[0].rendering.simple).toEqual({
      background_color: '#763EF0',
      text_color: '#FFFFFF',
    })
    expect(metadata.claims.map(claim => [claim.path[0], claim.sd])).toEqual([
      ['organization', 'never'],
      ['role', 'allowed'],
    ])
  })
})

describe('parseOfferClaims', () => {
  it('accepts and returns exactly the configured claims', () => {
    expect(parseOfferClaims(base, { organization: 'ACME', role: 'member', extra: 'ignored' })).toEqual({
      organization: 'ACME',
      role: 'member',
    })
  })
  it('rejects a missing, non-string, empty or oversized claim', () => {
    expect(() => parseOfferClaims(base, { organization: 'ACME' })).toThrow(/role/)
    expect(() => parseOfferClaims(base, { organization: 'ACME', role: 42 })).toThrow(/role/)
    expect(() => parseOfferClaims(base, { organization: '  ', role: 'r' })).toThrow(/organization/)
    expect(() => parseOfferClaims(base, { organization: 'o'.repeat(201), role: 'r' })).toThrow(/organization/)
  })
})
