import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { IssuerService } from '../src/services/IssuerService'
import { UnknownSessionError, VerifierService } from '../src/services/VerifierService'
import { GateBlockedError, WalletService } from '../src/services/WalletService'

import { startResolverStub } from './helpers/resolverStub'
import { startTestAgent } from './helpers/testAgent'

const ISSUER_DID = 'did:web:issuer.test'
const VERIFIER_DID = 'did:webvh:test:verifier'
const ROGUE_DID = 'did:web:rogue.example'
const VCT = 'https://issuer.test/vct/unfold-attestation'
const VTJSC = 'https://issuer.test/vt/schemas-unfold-attestation-jsc.json'

describe('full oid4vci to oid4vp flow with verana gate', () => {
  let stub: Awaited<ReturnType<typeof startResolverStub>>
  let issuer: Awaited<ReturnType<typeof startTestAgent>>
  let wallet: Awaited<ReturnType<typeof startTestAgent>>
  let verifier: Awaited<ReturnType<typeof startTestAgent>>
  let issuerService: IssuerService
  let walletService: WalletService
  let verifierService: VerifierService

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
      vct: VCT,
      vtjscId: VTJSC,
      rogueVerifierDid: ROGUE_DID,
    }
    ;[issuer, wallet, verifier] = await Promise.all([
      startTestAgent('issuer', { ...base, issuerEnabled: true }),
      startTestAgent('holder', { ...base, holderEnabled: true }),
      startTestAgent('verifier', { ...base, verifierEnabled: true }),
    ])
    // did-method issuer signing requires a real created DID record (not just a label) so
    // Credo can dereference the signing verification method and its kms key mapping.
    const issuerDidResult = await issuer.agent.dids.create({ method: 'web', domain: 'issuer.test' })
    if (issuerDidResult.didState.state !== 'finished' || issuerDidResult.didState.did !== ISSUER_DID) {
      throw new Error(
        `failed to create test issuer did:web record: ${JSON.stringify(issuerDidResult.didState)}`,
      )
    }
    issuer.agent.did = ISSUER_DID
    verifier.agent.did = VERIFIER_DID
    issuerService = new IssuerService(issuer.agent, issuer.options)
    walletService = new WalletService(wallet.agent, wallet.options)
    verifierService = new VerifierService(verifier.agent, verifier.options)
    await issuerService.ensureInitialized()
    await verifierService.ensureInitialized()

    // The wallet and the verifier both need to resolve the issuer's did:web to verify the
    // credential signature. Import it into their own storage so resolution stays local (no
    // real network access for the 'issuer.test' domain used in this suite).
    const [issuerDidRecord] = await issuer.agent.dids.getCreatedDids({ did: ISSUER_DID })
    if (!issuerDidRecord?.didDocument) {
      throw new Error('issuer did document not found after initialization')
    }
    await wallet.agent.dids.import({
      did: ISSUER_DID,
      didDocument: issuerDidRecord.didDocument,
      overwrite: true,
    })
    await verifier.agent.dids.import({
      did: ISSUER_DID,
      didDocument: issuerDidRecord.didDocument,
      overwrite: true,
    })
  }, 120000)

  afterAll(async () => {
    await Promise.all([issuer?.stop(), wallet?.stop(), verifier?.stop(), stub?.stop()])
  })

  it('issues an sd-jwt vc into the wallet via pre-authorized code', async () => {
    const { credentialOffer } = await issuerService.createOffer({ organization: 'ACME', role: 'employee' })
    const stored = await walletService.acceptOffer(credentialOffer)
    expect(stored.claims.organization).toBe('ACME')
    expect(stored.claims.role).toBe('employee')
    const { credentials } = await walletService.listCredentials()
    expect(credentials).toHaveLength(1)
  }, 60000)

  it('presents to the trusted verifier: verdict TRUSTED_AUTHORIZED, share succeeds, receipt has both verdicts', async () => {
    const { authorizationRequest, sessionId } = await verifierService.createRequest('trusted')
    const resolved = await walletService.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(resolved.request.verifierDid).toBe(VERIFIER_DID)

    const shared = await walletService.share(resolved.gateId)
    expect(shared.shared).toBe(true)

    const session = await verifierService.getSession(sessionId)
    expect(session.state).toBe('ResponseVerified')
    expect(session.receipt?.exchange.tenant).toBe('trusted')
    expect(session.receipt?.verifier.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(session.receipt?.verifier.did).toBe(VERIFIER_DID)
    expect(session.receipt?.issuer.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(session.receipt?.issuer.did).toBe(ISSUER_DID)
    expect(session.receipt?.credential.disclosedClaims.organization).toBe('ACME')
    expect(session.receipt?.credential.disclosedClaims.role).toBe('employee')
  }, 60000)

  it('single-use gate: a shared gate cannot be replayed', async () => {
    const { authorizationRequest } = await verifierService.createRequest('trusted')
    const resolved = await walletService.resolveRequest(authorizationRequest)
    await walletService.share(resolved.gateId)
    await expect(walletService.share(resolved.gateId)).rejects.toBeInstanceOf(GateBlockedError)
  }, 60000)

  it('blocks sharing with the rogue verifier: verdict UNTRUSTED, share throws', async () => {
    const { authorizationRequest } = await verifierService.createRequest('rogue')
    const resolved = await walletService.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('UNTRUSTED')
    expect(resolved.request.verifierDid).toBe(ROGUE_DID)
    await expect(walletService.share(resolved.gateId)).rejects.toBeInstanceOf(GateBlockedError)
  }, 60000)

  it('fails closed when the resolver is down', async () => {
    const downStub = await startResolverStub({ trusted: new Set(), authorized: new Set(), down: true })
    const isolatedWallet = new WalletService(wallet.agent, { ...wallet.options, resolverUrl: downStub.url })
    const { authorizationRequest } = await verifierService.createRequest('trusted')
    const resolved = await isolatedWallet.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('RESOLVER_UNAVAILABLE')
    await expect(isolatedWallet.share(resolved.gateId)).rejects.toBeInstanceOf(GateBlockedError)
    await downStub.stop()
  }, 60000)

  it('getSession with an unknown session id throws UnknownSessionError', async () => {
    await expect(verifierService.getSession('does-not-exist')).rejects.toBeInstanceOf(UnknownSessionError)
  }, 60000)

  it('getSession before a presentation returns state with no receipt and queries the resolver zero times', async () => {
    const cleanStub = await startResolverStub({ trusted: new Set(), authorized: new Set() })
    const freshVerifier = new VerifierService(verifier.agent, {
      ...verifier.options,
      resolverUrl: cleanStub.url,
    })
    const { sessionId } = await freshVerifier.createRequest('trusted')

    const session = await freshVerifier.getSession(sessionId)
    expect(session.state).not.toBe('ResponseVerified')
    expect(session.receipt).toBeUndefined()
    expect(cleanStub.requestCount).toBe(0)

    await cleanStub.stop()
  }, 60000)

  it('rogue receipt is labeled tenant rogue, binds to the rogue DID, and the verifier judges it UNTRUSTED', async () => {
    const permissiveStub = await startResolverStub({
      trusted: new Set([ISSUER_DID, ROGUE_DID]),
      authorized: new Set([ISSUER_DID, ROGUE_DID]),
    })
    const permissiveWallet = new WalletService(wallet.agent, {
      ...wallet.options,
      resolverUrl: permissiveStub.url,
    })

    const { authorizationRequest, sessionId } = await verifierService.createRequest('rogue')
    const resolved = await permissiveWallet.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(resolved.request.verifierDid).toBe(ROGUE_DID)

    const shared = await permissiveWallet.share(resolved.gateId)
    expect(shared.shared).toBe(true)

    const session = await verifierService.getSession(sessionId)
    expect(session.state).toBe('ResponseVerified')
    expect(session.receipt?.exchange.tenant).toBe('rogue')
    expect(session.receipt?.verifier.did).toBe(ROGUE_DID)
    expect(session.receipt?.verifier.verdict).toBe('UNTRUSTED')
    expect(session.receipt?.issuer.did).toBe(ISSUER_DID)
    expect(session.receipt?.issuer.verdict).toBe('TRUSTED_AUTHORIZED')

    await permissiveStub.stop()
  }, 60000)
})
