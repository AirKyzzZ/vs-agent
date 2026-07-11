import { describe, expect, it } from 'vitest'

import { buildReceipt } from '../src/services/receipt'

const evidence = (did: string) => ({
  did,
  trustStatus: 'TRUSTED' as const,
  authorized: true,
  vtjscId: 'https://jsc',
  queries: ['q1', 'q3'],
})

const input = {
  sessionId: 's1',
  verifierId: 'verifier',
  vct: 'https://vct',
  disclosedClaims: { organization: 'ACME', role: 'employee' },
  iss: 'https://issuer.example',
  verifier: { verdict: 'TRUSTED_AUTHORIZED' as const, evidence: evidence('did:webvh:verifier') },
  issuer: { verdict: 'TRUSTED_AUTHORIZED' as const, evidence: evidence('did:webvh:issuer') },
  vtjscId: 'https://jsc',
  verifiedAt: '2026-07-04T10:00:00.000Z',
}

describe('buildReceipt', () => {
  it('assembles both verdicts, claims and the configured registry reference', () => {
    const receipt = buildReceipt({
      ...input,
      registry: { network: 'vna-testnet-1', trustRegistry: 184, schema: 249 },
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
    expect(receipt.exchange).toMatchObject({
      protocol: 'OID4VP 1.0',
      sessionId: 's1',
      verifierId: 'verifier',
    })
  })

  it('falls back to just the vtjscId when no registry is configured', () => {
    expect(buildReceipt(input).registry).toEqual({ vtjscId: 'https://jsc' })
  })
})
