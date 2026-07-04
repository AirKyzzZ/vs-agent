import type { Server } from 'node:http'

import express from 'express'

export interface ResolverStubBehavior {
  trusted: Set<string>
  authorized: Set<string>
  down?: boolean
}

export interface ResolverStub {
  url: string
  requests: string[]
  requestCount: number
  reset: () => void
  stop: () => Promise<void>
}

export async function startResolverStub(behavior: ResolverStubBehavior): Promise<ResolverStub> {
  const requests: string[] = []
  const app = express()

  app.use((req, _res, next) => {
    requests.push(req.originalUrl)
    next()
  })

  app.get('/v1/trust/resolve', (req, res) => {
    if (behavior.down) return res.status(503).json({ error: 'down' })
    const did = String(req.query.did)
    if (!behavior.trusted.has(did)) return res.status(404).json({ error: 'not found' })
    return res.json({ did, trustStatus: 'TRUSTED', production: true })
  })

  const authHandler = (req: express.Request, res: express.Response) => {
    if (behavior.down) return res.status(503).json({ error: 'down' })
    const did = String(req.query.did)
    return res.json({ did, authorized: behavior.authorized.has(did) })
  }
  app.get('/v1/trust/verifier-authorization', authHandler)
  app.get('/v1/trust/issuer-authorization', authHandler)

  const server: Server = await new Promise(resolve => {
    const s = app.listen(0, () => resolve(s))
  })
  const port = (server.address() as { port: number }).port

  return {
    url: `http://127.0.0.1:${port}/v1/trust`,
    get requestCount() {
      return requests.length
    },
    requests,
    reset: () => {
      requests.length = 0
    },
    stop: () => new Promise(resolve => server.close(() => resolve())),
  }
}
