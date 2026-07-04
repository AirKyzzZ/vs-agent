import type { VsAgent } from '@verana-labs/vs-agent-sdk'

import { Kms, X509Certificate } from '@credo-ts/core'

export interface CertificateHandle {
  certificate: X509Certificate
  keyId: string
}

export async function ensureP256CertificateWithDidSan(
  agent: VsAgent,
  options: { genericRecordId: string; commonName: string; sanUri: string; sanDns: string },
): Promise<CertificateHandle> {
  const existing = await agent.genericRecords.findById(options.genericRecordId)
  if (existing) {
    const content = existing.content as { pem: string; keyId: string }
    const certificate = X509Certificate.fromEncodedCertificate(content.pem)
    certificate.keyId = content.keyId
    return { certificate, keyId: content.keyId }
  }

  const key = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  const certificate = await agent.x509.createCertificate({
    authorityKey: Kms.PublicJwk.fromPublicJwk(key.publicJwk),
    issuer: { commonName: options.commonName },
    validity: { notAfter: new Date(Date.now() + 2 * 365 * 24 * 3600 * 1000) },
    extensions: {
      subjectAlternativeName: {
        name: [
          { type: 'url', value: options.sanUri },
          { type: 'dns', value: options.sanDns },
        ],
      },
    },
  })
  certificate.keyId = key.keyId

  await agent.genericRecords.save({
    id: options.genericRecordId,
    content: { pem: certificate.toString('pem'), keyId: key.keyId },
  })
  return { certificate, keyId: key.keyId }
}
