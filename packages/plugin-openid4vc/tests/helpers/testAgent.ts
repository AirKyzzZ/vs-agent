import type { OpenId4VcPluginOptions } from '../../src/types'
import type { AskarModuleConfigStoreOptions, AskarSqliteStorageConfig } from '@credo-ts/askar'
import type { DidResolver } from '@credo-ts/core'
import type { Server } from 'node:http'

import { AskarModule } from '@credo-ts/askar'
import { Agent, ConsoleLogger, DidsModule, LogLevel, utils } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { askar } from '@openwallet-foundation/askar-nodejs'
import express from 'express'

import { setupOpenId4Vc } from '../../src/sdk/setupOpenId4Vc'

type Role = 'issuer' | 'verifier' | 'holder'

export interface TestAgent {
  agent: any
  options: OpenId4VcPluginOptions
  stop: () => Promise<void>
}

function askarStore(role: Role): AskarModuleConfigStoreOptions {
  return {
    id: `oid4vc-test-${role}-${utils.uuid().slice(0, 8)}`,
    key: 'DZ9hPqFWTPxemcGea72C1X1nusqk5wFNLq6QPjwXGqAa',
    keyDerivationMethod: 'raw',
    database: { type: 'sqlite', config: { inMemory: true } } as AskarSqliteStorageConfig,
  }
}

const LOG_LEVEL = process.env.OID4VC_TEST_LOG ? LogLevel.Debug : LogLevel.Off

export async function startTestAgent(
  role: Role,
  optionsBase: Omit<OpenId4VcPluginOptions, 'publicApiBaseUrl'>,
  didResolvers?: DidResolver[],
): Promise<TestAgent> {
  const app = express()
  const server: Server = await new Promise(resolve => {
    const s = app.listen(0, () => resolve(s))
  })
  const port = (server.address() as { port: number }).port
  const publicApiBaseUrl = `http://127.0.0.1:${port}`
  const options: OpenId4VcPluginOptions = { ...optionsBase, publicApiBaseUrl }

  const { modules } = setupOpenId4Vc(options, app)

  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(LOG_LEVEL),
      allowInsecureHttpUrls: true,
    },
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({ askar, store: askarStore(role) }),
      ...(didResolvers ? { dids: new DidsModule({ resolvers: didResolvers }) } : {}),
      ...modules,
    },
  })
  await agent.initialize()

  return {
    agent,
    options,
    stop: async () => {
      await agent.shutdown()
      await new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}
