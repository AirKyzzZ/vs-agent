import type { AgentContext, DidResolutionResult, DidResolver } from '@credo-ts/core'

import { DidDocument, JsonTransformer } from '@credo-ts/core'

/** Build a DID document whose only verification method (assertion + authentication) is `jwk`. */
export function didDocumentWithKey(did: string, jwk: Record<string, unknown>): DidDocument {
  const vmId = `${did}#key-1`
  return JsonTransformer.fromJSON(
    {
      id: did,
      verificationMethod: [{ id: vmId, type: 'JsonWebKey2020', controller: did, publicKeyJwk: jwk }],
      assertionMethod: [vmId],
      authentication: [vmId],
    },
    DidDocument,
  )
}

/** Resolves `did:webvh` test DIDs from a shared, mutable map (populated after keys are created). */
export class MapDidResolver implements DidResolver {
  public readonly supportedMethods = ['webvh']
  public readonly allowsCaching = false
  public readonly allowsLocalDidRecord = false

  public constructor(private readonly documents: Map<string, DidDocument>) {}

  public async resolve(_agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didDocument = this.documents.get(did) ?? null
    return {
      didDocument,
      didDocumentMetadata: {},
      didResolutionMetadata: didDocument ? {} : { error: 'notFound' },
    }
  }
}
