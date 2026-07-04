import type { TrustVerdict } from '../trust/types'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'

import { utils } from '@credo-ts/core'

export interface GateEntry extends TrustVerdict {
  resolved: OpenId4VpResolvedAuthorizationRequest
}

export class GateStore {
  private readonly entries = new Map<string, GateEntry>()

  public constructor(private readonly capacity = 200) {}

  public create(entry: GateEntry): string {
    if (this.entries.size >= this.capacity) {
      const oldest = this.entries.keys().next().value
      if (oldest) this.entries.delete(oldest)
    }
    const id = utils.uuid()
    this.entries.set(id, entry)
    return id
  }

  public get(id: string): GateEntry | undefined {
    return this.entries.get(id)
  }
}
