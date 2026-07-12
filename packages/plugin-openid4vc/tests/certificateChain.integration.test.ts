import type { OpenId4VcCredentialConfiguration } from '../src/types'
import type { DidDocument } from '@credo-ts/core'

import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { didFromCertificateSan, ensureP256CertificateWithDidSan } from '../src/services/AgentSetup'
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

describe('internal CA certificate chain (opt-in)', () => {
  let stub: Awaited<ReturnType<typeof startResolverStub>>
  let issuer: Awaited<ReturnType<typeof startTestAgent>>
  let wallet: Awaited<ReturnType<typeof startTestAgent>>
  let verifier: Awaited<ReturnType<typeof startTestAgent>>
  let issuerService: IssuerService
  let walletService: WalletService
  let verifierService: VerifierService
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
      certificateChain: { enabled: true },
    }
    const resolvers = [new MapDidResolver(didDocuments)]
    ;[issuer, wallet, verifier] = await Promise.all([
      startTestAgent('issuer', { ...base, issuerEnabled: true }, resolvers),
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

  it('issues the leaf from an internal root CA: a 2-cert chain with the DID in the leaf SAN', async () => {
    const chained = await ensureP256CertificateWithDidSan(issuer.agent, {
      genericRecordId: 'test-chain-cert',
      commonName: 'Test Issuer',
      sanUri: ISSUER_DID,
      sanDns: 'issuer.test',
      useCertificateChain: true,
    })
    expect(chained.chain).toHaveLength(2)
    expect(didFromCertificateSan(chained.chain[0])).toBe(ISSUER_DID)

    const selfSigned = await ensureP256CertificateWithDidSan(issuer.agent, {
      genericRecordId: 'test-selfsigned-cert',
      commonName: 'Test Issuer',
      sanUri: ISSUER_DID,
      sanDns: 'issuer.test',
    })
    expect(selfSigned.chain).toHaveLength(1)
  }, 60000)

  it('a chained credential still issues, presents and yields TRUSTED_AUTHORIZED', async () => {
    const { credentialOffer } = await issuerService.createOffer(CONFIG_ID, {
      organization: 'ACME',
      role: 'employee',
    })
    await walletService.acceptOffer(credentialOffer)

    const { authorizationRequest, sessionId } = await verifierService.createRequest()
    const resolved = await walletService.resolveRequest(authorizationRequest)
    expect(resolved.verdict).toBe('TRUSTED_AUTHORIZED')
    await walletService.share(resolved.gateId)

    const session = await verifierService.getSession(sessionId)
    expect(session.state).toBe('ResponseVerified')
    expect(session.receipt?.issuer.verdict).toBe('TRUSTED_AUTHORIZED')
    expect(session.receipt?.issuer.did).toBe(ISSUER_DID)
  }, 60000)
})
