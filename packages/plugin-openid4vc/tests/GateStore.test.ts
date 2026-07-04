import { describe, expect, it } from 'vitest'

import { GateStore } from '../src/services/GateStore'

describe('GateStore', () => {
  it('stores and retrieves a gate by generated id', () => {
    const store = new GateStore()
    const id = store.create({ verdict: 'TRUSTED_AUTHORIZED' } as any)
    expect(store.get(id)?.verdict).toBe('TRUSTED_AUTHORIZED')
  })
  it('returns undefined for unknown ids', () => {
    expect(new GateStore().get('nope')).toBeUndefined()
  })
  it('evicts oldest entries beyond capacity', () => {
    const store = new GateStore(2)
    const first = store.create({ verdict: 'UNTRUSTED' } as any)
    store.create({ verdict: 'UNTRUSTED' } as any)
    store.create({ verdict: 'UNTRUSTED' } as any)
    expect(store.get(first)).toBeUndefined()
  })
  it('consume returns the entry once and removes it', () => {
    const store = new GateStore()
    const id = store.create({ verdict: 'TRUSTED_AUTHORIZED' } as any)
    expect(store.consume(id)?.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(store.get(id)).toBeUndefined()
  })
})
