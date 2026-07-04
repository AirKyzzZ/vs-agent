import { describe, expect, it, vi } from 'vitest'
import { TrustClient } from '../src/trust/TrustClient'

const RESOLVER = 'https://resolver.example/v1/trust'
const DID = 'did:webvh:Qm123:verifier.example'

function fetchReturning(status: number, body?: unknown): typeof fetch {
  return vi.fn(async () =>
    new Response(body === undefined ? null : JSON.stringify(body), { status }),
  ) as unknown as typeof fetch
}

describe('TrustClient', () => {
  it('resolve maps 200 to ok with trustStatus', async () => {
    const client = new TrustClient(RESOLVER, fetchReturning(200, { did: DID, trustStatus: 'TRUSTED', production: true }))
    expect(await client.resolve(DID)).toMatchObject({ status: 'ok', trustStatus: 'TRUSTED' })
  })
  it('resolve maps 404 to not_found and 500 to unreachable', async () => {
    expect(await new TrustClient(RESOLVER, fetchReturning(404)).resolve(DID)).toEqual({ status: 'not_found' })
    expect(await new TrustClient(RESOLVER, fetchReturning(500)).resolve(DID)).toEqual({ status: 'unreachable' })
  })
  it('resolve maps network error to unreachable', async () => {
    const failing = vi.fn(async () => { throw new Error('ECONNREFUSED') }) as unknown as typeof fetch
    expect(await new TrustClient(RESOLVER, failing).resolve(DID)).toEqual({ status: 'unreachable' })
  })
  it('checkAuthorization returns boolean on 200, false on 404, null otherwise', async () => {
    expect(await new TrustClient(RESOLVER, fetchReturning(200, { authorized: true })).checkAuthorization('verifier', DID, 'https://jsc')).toBe(true)
    expect(await new TrustClient(RESOLVER, fetchReturning(404)).checkAuthorization('verifier', DID, 'https://jsc')).toBe(false)
    expect(await new TrustClient(RESOLVER, fetchReturning(503)).checkAuthorization('verifier', DID, 'https://jsc')).toBe(null)
  })
  it('verdictFor with null did is UNTRUSTED with note', async () => {
    const { verdict, evidence } = await new TrustClient(RESOLVER, fetchReturning(200, {})).verdictFor('verifier', null, 'https://jsc')
    expect(verdict).toBe('UNTRUSTED')
    expect(evidence.note).toContain('no DID')
  })
  it('verdictFor with null vtjscId never authorizes', async () => {
    const { verdict } = await new TrustClient(RESOLVER, fetchReturning(200, { trustStatus: 'TRUSTED' })).verdictFor('verifier', DID, null)
    expect(verdict).toBe('TRUSTED_NOT_AUTHORIZED')
  })
  it('verdictFor records the exact query urls in evidence', async () => {
    const { evidence } = await new TrustClient(RESOLVER, fetchReturning(200, { trustStatus: 'TRUSTED', authorized: true })).verdictFor('verifier', DID, 'https://jsc')
    expect(evidence.queries[0]).toBe(`${RESOLVER}/resolve?did=${encodeURIComponent(DID)}`)
    expect(evidence.queries[1]).toBe(`${RESOLVER}/verifier-authorization?did=${encodeURIComponent(DID)}&vtjscId=${encodeURIComponent('https://jsc')}`)
  })
})
