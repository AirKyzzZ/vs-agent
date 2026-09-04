import type { OpenId4VcCredentialConfiguration } from '../src/types'
import type { DidDocument, X509Certificate } from '@credo-ts/core'

import { getListFromStatusListJWT } from '@owf/token-status-list'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { OpenId4VcIssuanceSessionStateError } from '../src/services/IssuerService'

import { createCertificateFixtures } from './helpers/certificates'
import { didDocumentWithKey, MapDidResolver } from './helpers/didResolver'
import { startResolverStub } from './helpers/resolverStub'
import { createVerifierCertificate, startOpenId4VcTestAgents } from './helpers/testAgent'

const ISSUER_DID = 'did:web:issuer.example'
const VERIFIER_DID = 'did:web:verifier.example'
const CONFIGURATION: OpenId4VcCredentialConfiguration = {
  id: 'employee',
  format: 'dc+sd-jwt',
  vct: 'https://credentials.example/vct/employee',
  name: 'Employee credential',
  vtjscId: 'https://credentials.example/vt/employee.json',
  claims: ['name', 'role'],
  disclosureFrame: ['name', 'role'],
  ttlSeconds: 3_600,
}

describe('status list revocation', () => {
  let resolver: Awaited<ReturnType<typeof startResolverStub>>
  let agents: Awaited<ReturnType<typeof startOpenId4VcTestAgents>>

  async function start(size: number) {
    const certificates = await createCertificateFixtures()
    const verifierCertificate: X509Certificate = await createVerifierCertificate(
      certificates.root,
      VERIFIER_DID,
    )
    const didDocuments = new Map<string, DidDocument>([
      [ISSUER_DID, didDocumentWithKey(ISSUER_DID, certificates.leaf.publicJwk.toJson(), ['assertionMethod'])],
      [
        VERIFIER_DID,
        didDocumentWithKey(VERIFIER_DID, verifierCertificate.publicJwk.toJson(), ['authentication']),
      ],
    ])
    resolver = await startResolverStub({ trusted: new Set([ISSUER_DID]), authorized: new Set([ISSUER_DID]) })
    agents = await startOpenId4VcTestAgents({
      certificates,
      verifierCertificate,
      didResolver: new MapDidResolver(didDocuments),
      resolverUrl: resolver.url,
      issuerDid: ISSUER_DID,
      verifierDid: VERIFIER_DID,
      credentialConfiguration: CONFIGURATION,
      revocation: { enabled: true, size },
    })
  }

  async function issue() {
    const offer = await agents.issuer.service.createOffer(CONFIGURATION.id, {
      name: 'Ada Lovelace',
      role: 'engineer',
    })
    const credential = await agents.holder.acceptCredentialOffer(offer.credentialOffer)
    return { sessionId: offer.issuanceSessionId, credential }
  }

  beforeEach(async () => {
    await start(4)
  }, 60_000)

  afterEach(async () => {
    await Promise.allSettled([agents?.stop(), resolver?.stop()])
  })

  it('issues a credential with a status claim, serves the list, and flips the bit on revocation', async () => {
    const { sessionId, credential } = await issue()
    const status = credential.prettyClaims.status as { status_list: { idx: number; uri: string } }
    expect(status.status_list.uri.startsWith(`${agents.issuer.publicApiBaseUrl}/oid4vc/status-list/`)).toBe(
      true,
    )

    const before = await fetch(status.status_list.uri)
    expect(before.status).toBe(200)
    expect(before.headers.get('content-type')).toBe('application/statuslist+jwt')
    expect(getListFromStatusListJWT(await before.text()).getStatus(status.status_list.idx)).toBe(0)

    await agents.issuer.service.revokeIssuanceSession(sessionId)
    const after = await fetch(status.status_list.uri)
    expect(getListFromStatusListJWT(await after.text()).getStatus(status.status_list.idx)).toBe(1)

    await expect(agents.issuer.service.revokeIssuanceSession(sessionId)).resolves.toBeUndefined()
  }, 60_000)

  it('refuses to revoke an offer that no wallet accepted', async () => {
    const offer = await agents.issuer.service.createOffer(CONFIGURATION.id, {
      name: 'Ada Lovelace',
      role: 'engineer',
    })
    await expect(agents.issuer.service.revokeIssuanceSession(offer.issuanceSessionId)).rejects.toBeInstanceOf(
      OpenId4VcIssuanceSessionStateError,
    )
  }, 60_000)

  it('answers 404 for an unknown list', async () => {
    const response = await fetch(`${agents.issuer.publicApiBaseUrl}/oid4vc/status-list/unknown`)
    expect(response.status).toBe(404)
  }, 60_000)

  it('refuses the issuance that would exceed the list capacity', async () => {
    await Promise.allSettled([agents.stop(), resolver.stop()])
    await start(1)

    await issue()
    const second = await agents.issuer.service.createOffer(CONFIGURATION.id, {
      name: 'Grace Hopper',
      role: 'admiral',
    })
    await expect(agents.holder.acceptCredentialOffer(second.credentialOffer)).rejects.toThrow()
  }, 90_000)
})
