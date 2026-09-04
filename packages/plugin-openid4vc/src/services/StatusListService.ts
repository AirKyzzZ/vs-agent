import type { SigningCertificateHandle } from './CertificateService'
import type { BaseAgent } from '@credo-ts/core'

import { TokenStatusListApi, utils } from '@credo-ts/core'
import { getListFromStatusListJWT } from '@owf/token-status-list'

const RECORD_ID = 'oid4vc-status-list'
const DEFAULT_SIZE = 131072
const BITS_PER_STATUS = 1
const STATUS_REVOKED = 1
const SIGNING_ALG = 'ES256' as const

export type StatusListAgent = Pick<BaseAgent, 'genericRecords' | 'dependencyManager'>

export interface StatusReference {
  status_list: { idx: number; uri: string }
}

interface StatusListState {
  listId: string
  uri: string
  size: number
  nextIndex: number
  token: string
  sessionIndices: Record<string, number[]>
  revoked: number[]
}

export class StatusListEntryNotFoundError extends Error {}

export class StatusListService {
  private state?: StatusListState
  private queue: Promise<unknown> = Promise.resolve()

  public constructor(
    private readonly agent: StatusListAgent,
    private readonly certificate: SigningCertificateHandle,
    private readonly baseUrl: string,
    private readonly size: number = DEFAULT_SIZE,
  ) {
    if (!Number.isInteger(this.size) || this.size <= 0) {
      throw new Error(`revocation status list size must be a positive integer, got ${this.size}`)
    }
  }

  public async initialize(): Promise<void> {
    if (this.state) return
    const existing = await this.agent.genericRecords.findById(RECORD_ID)
    if (existing) {
      this.state = existing.content as unknown as StatusListState
      return
    }
    const listId = utils.uuid()
    const uri = `${this.baseUrl}/oid4vc/status-list/${listId}`
    const { statusList: token } = await this.api().createTokenStatusList<'jwt'>({
      format: 'jwt',
      statusList: { statusListLength: this.size, bitsPerStatus: BITS_PER_STATUS },
      statusListUri: uri,
      signer: this.signer(),
      alg: SIGNING_ALG,
    })
    this.state = { listId, uri, size: this.size, nextIndex: 0, token, sessionIndices: {}, revoked: [] }
    await this.persist()
  }

  public allocate(issuanceSessionId: string): Promise<StatusReference> {
    return this.withLock(async () => {
      const state = this.requireState()
      if (state.nextIndex >= state.size) throw new Error('status list capacity exhausted')
      const idx = state.nextIndex
      state.nextIndex += 1
      ;(state.sessionIndices[issuanceSessionId] ??= []).push(idx)
      await this.persist()
      return { status_list: { idx, uri: state.uri } }
    })
  }

  public revoke(issuanceSessionId: string): Promise<number[]> {
    return this.withLock(async () => {
      const state = this.requireState()
      const indices = state.sessionIndices[issuanceSessionId]
      if (!indices || indices.length === 0) {
        throw new StatusListEntryNotFoundError(
          `no issued credential found for session '${issuanceSessionId}'`,
        )
      }
      const toRevoke = indices.filter(index => !state.revoked.includes(index))
      if (toRevoke.length > 0) {
        // Re-signs through createTokenStatusList rather than updateTokenStatusList: Credo's update path reads `alg` off the KMS key, unset on our P-256 cert key, and fails to sign.
        const list = getListFromStatusListJWT(state.token)
        for (const index of toRevoke) list.setStatus(index, STATUS_REVOKED)
        const { statusList: token } = await this.api().createTokenStatusList<'jwt'>({
          format: 'jwt',
          statusList: list,
          statusListUri: state.uri,
          signer: this.signer(),
          alg: SIGNING_ALG,
        })
        state.token = token
        state.revoked.push(...toRevoke)
        await this.persist()
      }
      return indices
    })
  }

  public getToken(listId: string): string | undefined {
    if (!this.state || this.state.listId !== listId) return undefined
    return this.state.token
  }

  private withLock<T>(fn: () => Promise<T>): Promise<T> {
    const result = this.queue.then(
      () => fn(),
      () => fn(),
    )
    this.queue = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  private api(): TokenStatusListApi {
    return this.agent.dependencyManager.resolve(TokenStatusListApi)
  }

  private signer() {
    return { method: 'x5c' as const, x5c: this.certificate.chain }
  }

  private requireState(): StatusListState {
    if (!this.state) throw new Error('status list not initialized')
    return this.state
  }

  private async persist(): Promise<void> {
    const content = JSON.parse(JSON.stringify(this.requireState())) as Record<string, unknown>
    const record = await this.agent.genericRecords.findById(RECORD_ID)
    if (record) {
      record.content = content
      await this.agent.genericRecords.update(record)
    } else {
      await this.agent.genericRecords.save({ id: RECORD_ID, content })
    }
  }
}
