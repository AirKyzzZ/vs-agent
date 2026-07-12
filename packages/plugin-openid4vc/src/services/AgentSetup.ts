import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { Kms, VerificationMethod, X509Certificate, X509KeyUsage } from '@credo-ts/core'

export interface CertificateHandle {
  /** the signing (leaf) certificate; its key signs credentials, OID4VP requests and status lists */
  certificate: X509Certificate
  keyId: string
  /** the x5c chain, leaf-first: `[leaf]` when self-signed, `[leaf, root]` when issued from an internal CA */
  chain: X509Certificate[]
}

interface StoredCertificate {
  pem: string
  keyId: string
  chainPem?: string[]
}

const TWO_YEARS_MS = 2 * 365 * 24 * 3600 * 1000
const FIVE_YEARS_MS = 5 * 365 * 24 * 3600 * 1000

export function didFromCertificateSan(certificate: X509Certificate | undefined): string | null {
  return certificate?.sanUriNames.find(uri => uri.startsWith('did:')) ?? null
}

/**
 * Publish the P-256 signing key of `certificate` into this agent's DID document under the given
 * verification relationships, so a peer can authenticate the DID→key binding (the fail-closed trust
 * gate resolves the DID and requires the signing key to be present). Issuers publish it as
 * `assertionMethod`; verifiers, whose request key authenticates them, publish it as `authentication`
 * too. Idempotent and best-effort: a resolvable DID that never gains the key simply fails closed.
 */
export async function publishSigningKeyInDidDocument(
  agent: VsAgent,
  certificate: CertificateHandle,
  relationships: Array<'authentication' | 'assertionMethod'>,
): Promise<void> {
  if (!agent.did) return
  try {
    const [didRecord] = await agent.dids.getCreatedDids({ did: agent.did })
    const didDocument = didRecord?.didDocument
    if (!didDocument) return
    const methodId = `${agent.did}#oid4vc-es256`
    if (didDocument.verificationMethod?.some(vm => vm.id === methodId)) return
    didDocument.verificationMethod = [
      ...(didDocument.verificationMethod ?? []),
      new VerificationMethod({
        id: methodId,
        type: 'JsonWebKey2020',
        controller: agent.did,
        publicKeyJwk: certificate.certificate.publicJwk.toJson(),
      }),
    ]
    if (relationships.includes('assertionMethod')) {
      didDocument.assertionMethod = [...(didDocument.assertionMethod ?? []), methodId]
    }
    if (relationships.includes('authentication')) {
      didDocument.authentication = [...(didDocument.authentication ?? []), methodId]
    }
    await agent.dids.update({ did: agent.did, didDocument })
  } catch (error) {
    agent.config.logger.warn(`could not publish ES256 signing key in DID document: ${error}`)
  }
}

/**
 * Ensure a persisted P-256 signing certificate whose SAN carries the agent DID (the anchor Verana
 * resolves). Self-signed by default. With `useCertificateChain`, the leaf is issued from an internal
 * root CA and the returned `chain` is `[leaf, root]` (HAIP §5.1 non-self-signed leaf); the root is
 * kept in the x5c so the chain stays self-contained for wallets. Opt-in: the default self-signed path
 * is unchanged, so existing wallet interop is untouched.
 */
export async function ensureP256CertificateWithDidSan(
  agent: VsAgent,
  options: {
    genericRecordId: string
    commonName: string
    sanUri: string
    sanDns: string
    useCertificateChain?: boolean
  },
): Promise<CertificateHandle> {
  const existing = await agent.genericRecords.findById(options.genericRecordId)
  if (existing) {
    const content = existing.content as unknown as StoredCertificate
    const certificate = X509Certificate.fromEncodedCertificate(content.pem)
    certificate.keyId = content.keyId
    const chain = content.chainPem
      ? content.chainPem.map(pem => X509Certificate.fromEncodedCertificate(pem))
      : [certificate]
    return { certificate, keyId: content.keyId, chain }
  }

  const leafKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  const subjectAlternativeName = {
    name: [
      { type: 'url' as const, value: options.sanUri },
      { type: 'dns' as const, value: options.sanDns },
    ],
  }

  if (options.useCertificateChain) {
    const caKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const rootCommonName = `${options.commonName} Root CA`
    const root = await agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(caKey.publicJwk),
      issuer: { commonName: rootCommonName },
      validity: { notAfter: new Date(Date.now() + FIVE_YEARS_MS) },
      extensions: {
        basicConstraints: { ca: true, pathLenConstraint: 0 },
        keyUsage: { usages: [X509KeyUsage.KeyCertSign, X509KeyUsage.CrlSign] },
      },
    })
    root.keyId = caKey.keyId
    const leaf = await agent.x509.createCertificate({
      authorityKey: Kms.PublicJwk.fromPublicJwk(caKey.publicJwk),
      subjectPublicKey: Kms.PublicJwk.fromPublicJwk(leafKey.publicJwk),
      issuer: { commonName: rootCommonName },
      subject: { commonName: options.commonName },
      validity: { notAfter: new Date(Date.now() + TWO_YEARS_MS) },
      extensions: {
        subjectAlternativeName,
        basicConstraints: { ca: false },
        keyUsage: { usages: [X509KeyUsage.DigitalSignature] },
      },
    })
    leaf.keyId = leafKey.keyId
    const chain = [leaf, root]
    await agent.genericRecords.save({
      id: options.genericRecordId,
      content: {
        pem: leaf.toString('pem'),
        keyId: leafKey.keyId,
        chainPem: chain.map(certificate => certificate.toString('pem')),
      },
    })
    return { certificate: leaf, keyId: leafKey.keyId, chain }
  }

  const certificate = await agent.x509.createCertificate({
    authorityKey: Kms.PublicJwk.fromPublicJwk(leafKey.publicJwk),
    issuer: { commonName: options.commonName },
    validity: { notAfter: new Date(Date.now() + TWO_YEARS_MS) },
    extensions: { subjectAlternativeName },
  })
  certificate.keyId = leafKey.keyId
  await agent.genericRecords.save({
    id: options.genericRecordId,
    content: { pem: certificate.toString('pem'), keyId: leafKey.keyId },
  })
  return { certificate, keyId: leafKey.keyId, chain: [certificate] }
}
