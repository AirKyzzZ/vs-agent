import { describe, expect, it } from 'vitest'

import { withClientAttestationMetadata } from '../src/sdk/setupOpenId4Vc'

describe('withClientAttestationMetadata', () => {
  it('advertises attestation-based client auth on the authorization-server metadata', () => {
    const input = JSON.stringify({
      issuer: 'https://issuer.example',
      token_endpoint: 'https://issuer.example/token',
    })
    const out = JSON.parse(withClientAttestationMetadata(input))
    expect(out.token_endpoint_auth_methods_supported).toContain('attest_jwt_client_auth')
    expect(out.client_attestation_pop_signing_alg_values_supported).toEqual(['ES256'])
    expect(out.client_attestation_signing_alg_values_supported).toEqual(['ES256'])
    expect(out.issuer).toBe('https://issuer.example')
  })

  it('does not duplicate an already-advertised auth method', () => {
    const input = JSON.stringify({
      token_endpoint_auth_methods_supported: ['attest_jwt_client_auth', 'public'],
    })
    const out = JSON.parse(withClientAttestationMetadata(input))
    expect(out.token_endpoint_auth_methods_supported).toEqual(['attest_jwt_client_auth', 'public'])
  })

  it('passes through non-JSON and non-object bodies unchanged', () => {
    expect(withClientAttestationMetadata('not json')).toBe('not json')
    expect(withClientAttestationMetadata('[1,2,3]')).toBe('[1,2,3]')
    expect(withClientAttestationMetadata('"a string"')).toBe('"a string"')
  })
})
