import type { OpenId4VcPluginOptions } from '../src/types'

import { describe, expect, it } from 'vitest'

import { buildSdJwtPayload, resolveIssuerId } from '../src/services/IssuerService'

describe('buildSdJwtPayload', () => {
  it('builds vct, a subject id under the vct origin, and spreads the claims', () => {
    const payload = buildSdJwtPayload('https://issuer.example/vct/org-attestation', {
      organization: 'ACME',
      role: 'employee',
    })
    expect(payload).toMatchObject({
      vct: 'https://issuer.example/vct/org-attestation',
      organization: 'ACME',
      role: 'employee',
    })
    expect(String((payload as { id: string }).id)).toMatch(/^https:\/\/issuer\.example\/subjects\//)
  })

  it('includes a status reference only when one is provided', () => {
    const withStatus = buildSdJwtPayload(
      'https://issuer.example/vct/org-attestation',
      { organization: 'ACME' },
      { status_list: { idx: 7, uri: 'https://issuer.example/oid4vc/status-list/abc' } },
    )
    expect(withStatus).toMatchObject({
      status: { status_list: { idx: 7, uri: 'https://issuer.example/oid4vc/status-list/abc' } },
    })

    const withoutStatus = buildSdJwtPayload('https://issuer.example/vct/x', { a: 'b' })
    expect('status' in withoutStatus).toBe(false)
  })
})

describe('resolveIssuerId', () => {
  const base: OpenId4VcPluginOptions = {
    publicApiBaseUrl: 'https://issuer.example',
    issuerEnabled: true,
    verifierEnabled: false,
    holderEnabled: false,
    resolverUrl: 'https://resolver.example',
    credentialConfigurations: [],
  }

  it('defaults to "issuer" and honors an explicit id', () => {
    expect(resolveIssuerId(base)).toBe('issuer')
    expect(resolveIssuerId({ ...base, issuerId: 'org' })).toBe('org')
  })
})
