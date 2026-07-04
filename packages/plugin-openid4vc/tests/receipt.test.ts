import { describe, expect, it } from 'vitest'

import { buildReceipt } from '../src/services/receipt'

const evidence = (did: string) => ({
  did,
  trustStatus: 'TRUSTED' as const,
  authorized: true,
  vtjscId: 'https://jsc',
  queries: ['q1', 'q3'],
})

describe('buildReceipt', () => {
  it('assembles both verdicts, claims and registry references', () => {
    const receipt = buildReceipt({
      sessionId: 's1',
      tenant: 'trusted',
      vct: 'https://vct',
      disclosedClaims: { organization: 'ACME', role: 'employee' },
      iss: 'https://issuer.example',
      verifier: { verdict: 'TRUSTED_AUTHORIZED', evidence: evidence('did:webvh:verifier') },
      issuer: { verdict: 'TRUSTED_AUTHORIZED', evidence: evidence('did:webvh:issuer') },
      vtjscId: 'https://jsc',
      verifiedAt: '2026-07-04T10:00:00.000Z',
    })
    expect(receipt.registry).toEqual({
      network: 'vna-testnet-1',
      trustRegistry: 184,
      schema: 249,
      vtjscId: 'https://jsc',
    })
    expect(receipt.verifier.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(receipt.issuer.did).toBe('did:webvh:issuer')
    expect(receipt.credential.disclosedClaims.organization).toBe('ACME')
    expect(receipt.exchange).toMatchObject({ protocol: 'OID4VP 1.0', sessionId: 's1', tenant: 'trusted' })
  })
})
