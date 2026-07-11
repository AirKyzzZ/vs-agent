import type { TrustVerdict } from './types'
import type { OpenId4VcAgentModules } from '../types'
import type { DidDocument, VerificationMethod } from '@credo-ts/core'
import type { VsAgent } from '@verana-labs/vs-agent-sdk'

export type KeyBindingResult = 'bound' | 'unbound' | 'unresolvable'
export type VerificationRelationship = 'assertionMethod' | 'authentication'

/**
 * Canonical public-key material (the RFC 7638 thumbprint preimage) for exact key equality.
 * Two keys are the same iff this string matches; private members are never read.
 */
export function canonicalPublicKey(jwk: Record<string, unknown> | undefined | null): string | null {
  if (!jwk || typeof jwk.kty !== 'string') return null
  if (
    jwk.kty === 'EC' &&
    typeof jwk.crv === 'string' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string'
  ) {
    return `EC.${jwk.crv}.${jwk.x}.${jwk.y}`
  }
  if (jwk.kty === 'OKP' && typeof jwk.crv === 'string' && typeof jwk.x === 'string') {
    return `OKP.${jwk.crv}.${jwk.x}`
  }
  if (jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string') {
    return `RSA.${jwk.n}.${jwk.e}`
  }
  return null
}

function collectVerificationMethods(
  didDocument: DidDocument,
  relationships: VerificationRelationship[],
): VerificationMethod[] {
  const methods: VerificationMethod[] = []
  for (const relationship of relationships) {
    for (const entry of didDocument[relationship] ?? []) {
      if (typeof entry === 'string') {
        try {
          methods.push(didDocument.dereferenceVerificationMethod(entry))
        } catch {
          // dangling reference: skip
        }
      } else {
        methods.push(entry)
      }
    }
  }
  return methods
}

/**
 * Authenticate the DID -> signing-key binding: verify the exact `signingKeyJwk` is published,
 * under one of `relationships`, in the DID Document that `did` resolves to. This is the control
 * that stops a self-signed cert from asserting an arbitrary (trusted) DID in its SAN.
 *
 * Fail-closed: resolution error / no document -> 'unresolvable'; key absent -> 'unbound'.
 */
export async function verifyKeyBoundToDid(
  agent: VsAgent<OpenId4VcAgentModules>,
  did: string | null,
  signingKeyJwk: Record<string, unknown> | undefined,
  relationships: VerificationRelationship[],
): Promise<KeyBindingResult> {
  const target = canonicalPublicKey(signingKeyJwk)
  if (!did || !target) return 'unbound'
  let didDocument: DidDocument | undefined
  try {
    const result = await agent.dids.resolve(did)
    didDocument = result.didDocument ?? undefined
  } catch {
    return 'unresolvable'
  }
  if (!didDocument) return 'unresolvable'
  const methods = collectVerificationMethods(didDocument, relationships)
  const bound = methods.some(
    method => canonicalPublicKey(method.publicKeyJwk as Record<string, unknown> | undefined) === target,
  )
  return bound ? 'bound' : 'unbound'
}

/**
 * A blocking Verana verdict for a failed key binding, produced WITHOUT querying the resolver on a
 * spoofable DID. Maps into the same fail-closed sink: unresolvable -> RESOLVER_UNAVAILABLE, key not
 * bound -> UNTRUSTED. Never yields TRUSTED_AUTHORIZED.
 */
export function blockingBindingVerdict(
  did: string | null,
  vtjscId: string | null,
  result: Exclude<KeyBindingResult, 'bound'>,
): TrustVerdict {
  return {
    verdict: result === 'unresolvable' ? 'RESOLVER_UNAVAILABLE' : 'UNTRUSTED',
    evidence: {
      did,
      trustStatus: null,
      authorized: null,
      vtjscId,
      queries: [],
      note:
        result === 'unresolvable'
          ? 'the DID document for the asserted party could not be resolved'
          : 'the signing key is not bound to the asserted party DID',
    },
  }
}
