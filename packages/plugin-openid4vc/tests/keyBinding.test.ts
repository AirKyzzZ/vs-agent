import type { OpenId4VcAgentModules } from '../src/types'
import type { DidDocument, VerificationMethod } from '@credo-ts/core'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { describe, expect, it } from 'vitest'

import { blockingBindingVerdict, verifyKeyBoundToDid } from '../src/trust/keyBinding'

const K1 = { kty: 'EC', crv: 'P-256', x: 'k1-x-value', y: 'k1-y-value' }
const K2 = { kty: 'EC', crv: 'P-256', x: 'k2-x-value', y: 'k2-y-value' }
const DID = 'did:webvh:example:issuer'

function vm(jwk: Record<string, unknown>): VerificationMethod {
  return {
    id: `${DID}#k`,
    type: 'JsonWebKey2020',
    controller: DID,
    publicKeyJwk: jwk,
  } as unknown as VerificationMethod
}

function doc(
  fields: Partial<Record<'assertionMethod' | 'authentication', unknown[]>> & {
    deref?: Record<string, unknown>
  },
): DidDocument {
  return {
    assertionMethod: fields.assertionMethod,
    authentication: fields.authentication,
    dereferenceVerificationMethod: (id: string) => {
      const found = fields.deref?.[id]
      if (!found) throw new Error('dangling reference')
      return found
    },
  } as unknown as DidDocument
}

function agentResolving(
  impl: (did: string) => Promise<{ didDocument: DidDocument | null }>,
): VsAgent<OpenId4VcAgentModules> {
  return { dids: { resolve: impl } } as unknown as VsAgent<OpenId4VcAgentModules>
}

describe('verifyKeyBoundToDid', () => {
  it('binds when the exact signing key is an assertionMethod of the resolved DID document', async () => {
    const agent = agentResolving(async () => ({ didDocument: doc({ assertionMethod: [vm(K1)] }) }))
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['assertionMethod'])).toBe('bound')
  })

  it('dereferences a string assertionMethod reference and binds', async () => {
    const agent = agentResolving(async () => ({
      didDocument: doc({ assertionMethod: [`${DID}#k`], deref: { [`${DID}#k`]: vm(K1) } }),
    }))
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['assertionMethod'])).toBe('bound')
  })

  it('REJECTS a spoofed SAN: DID resolves but the signing key is not in the document (the core exploit)', async () => {
    const agent = agentResolving(async () => ({ didDocument: doc({ assertionMethod: [vm(K2)] }) }))
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['assertionMethod'])).toBe('unbound')
  })

  it('REJECTS key substitution: a different, legitimate key of the same DID does not bind our signing key', async () => {
    const agent = agentResolving(async () => ({
      didDocument: doc({ assertionMethod: [vm(K2), vm({ ...K2, x: 'other' })] }),
    }))
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['assertionMethod'])).toBe('unbound')
  })

  it('enforces the relationship: a key only under authentication does not satisfy an assertionMethod check', async () => {
    const agent = agentResolving(async () => ({ didDocument: doc({ authentication: [vm(K1)] }) }))
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['assertionMethod'])).toBe('unbound')
    expect(await verifyKeyBoundToDid(agent, DID, K1, ['authentication'])).toBe('bound')
  })

  it('fails closed when the DID cannot be resolved (throws or no document)', async () => {
    const throwing = agentResolving(async () => {
      throw new Error('network')
    })
    const empty = agentResolving(async () => ({ didDocument: null }))
    expect(await verifyKeyBoundToDid(throwing, DID, K1, ['assertionMethod'])).toBe('unresolvable')
    expect(await verifyKeyBoundToDid(empty, DID, K1, ['assertionMethod'])).toBe('unresolvable')
  })

  it('returns unbound for a null DID or an unusable signing key', async () => {
    const agent = agentResolving(async () => ({ didDocument: doc({ assertionMethod: [vm(K1)] }) }))
    expect(await verifyKeyBoundToDid(agent, null, K1, ['assertionMethod'])).toBe('unbound')
    expect(await verifyKeyBoundToDid(agent, DID, { kty: 'EC', crv: 'P-256' }, ['assertionMethod'])).toBe(
      'unbound',
    )
    expect(await verifyKeyBoundToDid(agent, DID, undefined, ['assertionMethod'])).toBe('unbound')
  })
})

describe('blockingBindingVerdict', () => {
  it('maps binding failure into the fail-closed sink and never passes', () => {
    expect(blockingBindingVerdict(DID, 'https://jsc', 'unresolvable').verdict).toBe('RESOLVER_UNAVAILABLE')
    expect(blockingBindingVerdict(DID, 'https://jsc', 'unbound').verdict).toBe('UNTRUSTED')
    expect(blockingBindingVerdict(DID, 'https://jsc', 'unbound').evidence.authorized).toBeNull()
  })
})
