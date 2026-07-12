import type { OpenId4VcCredentialConfiguration } from '../src/types'
import type { DidDocument } from '@credo-ts/core'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { getIssuerSigningJwk, IssuerService } from '../src/services/IssuerService'
import { VerifierService } from '../src/services/VerifierService'
import { WalletService } from '../src/services/WalletService'

import { didDocumentWithKey, MapDidResolver } from './helpers/didResolver'
import { startResolverStub } from './helpers/resolverStub'
import { startTestAgent } from './helpers/testAgent'

const ISSUER_DID = 'did:webvh:test:issuer'
const VERIFIER_DID = 'did:webvh:test:verifier'
const VCT = 'https://issuer.test/vct/org-attestation'
const VTJSC = 'https://issuer.test/vt/schemas-org-jsc.json'
const CONFIG_ID = 'org-attestation'

const CREDENTIAL_CONFIGURATION: OpenId4VcCredentialConfiguration = {
  id: CONFIG_ID,
  vct: VCT,
  name: 'Org Attestation',
  vtjscId: VTJSC,
  claims: ['organization', 'role'],
}

describe('token status list revocation', () => {
  let stub: Awaited<ReturnType<typeof startResolverStub>>
  let issuer: Awaited<ReturnType<typeof startTestAgent>>
  let wallet: Awaited<ReturnType<typeof startTestAgent>>
  let verifier: Awaited<ReturnType<typeof startTestAgent>>
  let issuerService: IssuerService
  let walletService: WalletService
  let verifierService: VerifierService
  let revocableSessionId: string
  const didDocuments = new Map<string, DidDocument>()

  beforeAll(async () => {
    stub = await startResolverStub({
      trusted: new Set([ISSUER_DID, VERIFIER_DID]),
      authorized: new Set([ISSUER_DID, VERIFIER_DID]),
    })
    const base = {
      issuerEnabled: false,
      verifierEnabled: false,
      holderEnabled: false,
      resolverUrl: stub.url,
      credentialConfigurations: [CREDENTIAL_CONFIGURATION],
    }
    const resolvers = [new MapDidResolver(didDocuments)]
    ;[issuer, wallet, verifier] = await Promise.all([
      startTestAgent('issuer', { ...base, issuerEnabled: true, revocation: { enabled: true } }, resolvers),
      startTestAgent('holder', { ...base, holderEnabled: true }, resolvers),
      startTestAgent('verifier', { ...base, verifierEnabled: true }, resolvers),
    ])
    issuer.agent.did = ISSUER_DID
    verifier.agent.did = VERIFIER_DID
    issuerService = new IssuerService(issuer.agent, issuer.options)
    walletService = new WalletService(wallet.agent, wallet.options)
    verifierService = new VerifierService(verifier.agent, verifier.options)
    await issuerService.ensureInitialized()
    await verifierService.ensureInitialized()

    const issuerJwk = getIssuerSigningJwk()
    const verifierJwk = verifierService.getSigningJwk()
    if (!issuerJwk || !verifierJwk) throw new Error('signing keys not initialized')
    didDocuments.set(ISSUER_DID, didDocumentWithKey(ISSUER_DID, issuerJwk))
    didDocuments.set(VERIFIER_DID, didDocumentWithKey(VERIFIER_DID, verifierJwk))
  }, 120000)

  afterAll(async () => {
    await Promise.all([issuer?.stop(), wallet?.stop(), verifier?.stop(), stub?.stop()])
  })

  it('issues a credential carrying a status reference that verifies as valid', async () => {
    const { credentialOffer, issuanceSessionId } = await issuerService.createOffer(CONFIG_ID, {
      organization: 'ACME',
      role: 'employee',
    })
    revocableSessionId = issuanceSessionId
    const stored = await walletService.acceptOffer(credentialOffer)
    expect(stored.claims.organization).toBe('ACME')

    const { authorizationRequest, sessionId } = await verifierService.createRequest()
    const resolved = await walletService.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('TRUSTED_AUTHORIZED')
    await walletService.share(resolved.gateId)

    const session = await verifierService.getSession(sessionId)
    expect(session.state).toBe('ResponseVerified')
    expect(session.receipt?.credential.credentialStatus).toBe('valid')
  }, 60000)

  it('rejects revocation of an unknown issuance session', async () => {
    await expect(issuerService.revoke('not-a-real-session')).rejects.toThrow(/no issued credential/)
  }, 60000)

  it('revokes the credential; it then fails verification (fail-closed) and revoke is idempotent', async () => {
    const revoked = await issuerService.revoke(revocableSessionId)
    expect(revoked.length).toBeGreaterThan(0)
    expect(await issuerService.revoke(revocableSessionId)).toEqual(revoked)

    let verified = false
    try {
      const { authorizationRequest, sessionId } = await verifierService.createRequest()
      const resolved = await walletService.resolveRequest(authorizationRequest)
      await walletService.share(resolved.gateId)
      const session = await verifierService.getSession(sessionId)
      verified = session.state === 'ResponseVerified'
    } catch {
      verified = false
    }
    expect(verified).toBe(false)
  }, 60000)
})
