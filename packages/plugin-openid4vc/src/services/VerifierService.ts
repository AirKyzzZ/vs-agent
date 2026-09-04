import type { OpenId4VcPluginOptions } from '../types'
import type { BaseAgent } from '@credo-ts/core'
import type {
  OpenId4VcVerificationSessionRecord,
  OpenId4VcVerifierApi,
  OpenId4VpVerifiedAuthorizationResponse,
} from '@credo-ts/openid4vc'

import { RecordNotFoundError } from '@credo-ts/core'
import { OpenId4VcVerificationSessionState } from '@credo-ts/openid4vc'

import { findCredentialConfiguration, findVerifierPolicy } from '../config'
import { TrustClient } from '../trust/TrustClient'
import {
  findBoundVerificationMethodId,
  findEd25519VerificationMethodId,
  ownDidResolutionPolicy,
  verifyKeyBoundToDid,
} from '../trust/keyBinding'
import { publishParallelWebSigningKey } from '../trust/parallelWebSigningKey'

import {
  didFromValidatedCertificate,
  loadSigningCertificate,
  publishDevelopmentSigningKey,
  signingCertificateInfo,
  type SigningCertificateHandle,
  type SigningCertificateInfo,
} from './CertificateService'
import { presentationQueryFor, type OpenId4VcQueryLanguage } from './presentationRequest'
import { decidePresentation, type PresentationDecision } from './presentationVerification'

type VerifierApi = Pick<
  OpenId4VcVerifierApi,
  | 'getVerifierByVerifierId'
  | 'createVerifier'
  | 'updateVerifierMetadata'
  | 'createAuthorizationRequest'
  | 'getVerificationSessionById'
  | 'getVerifiedAuthorizationResponse'
>

export type OpenId4VcVerifierAgent = Pick<
  BaseAgent,
  'dids' | 'genericRecords' | 'kms' | 'x509' | 'dependencyManager'
> & {
  did?: string
  modules: {
    openId4Vc?: {
      verifier?: VerifierApi
    }
  }
}

export type { OpenId4VcQueryLanguage } from './presentationRequest'

export interface OpenId4VcVerificationRequest {
  authorizationRequest: string
  verificationSessionId: string
}

export type { OpenId4VcVerifiedCredentialResult } from './presentationVerification'

export type OpenId4VcVerificationResult = PresentationDecision & {
  state: OpenId4VcVerificationSessionRecord['state']
}

export class OpenId4VcVerifierRequestError extends Error {}
export class UnknownVerificationSessionError extends Error {}

export class VerifierService {
  private initialization?: Promise<void>
  private signingCertificate?: SigningCertificateHandle
  private parallelWebSigningDidUrl?: string
  private initialized = false
  private readonly trustClient: TrustClient

  public constructor(
    private readonly agent: OpenId4VcVerifierAgent,
    private readonly options: OpenId4VcPluginOptions,
  ) {
    const trust = this.options.trust
    if (!trust) throw new Error('OpenID4VC verifier requires trust configuration')
    this.trustClient = new TrustClient(trust)
  }

  public ensureInitialized(): Promise<void> {
    // A rejected initialization must not be cached: a transient boot-time
    // failure (KMS or storage not ready yet) would otherwise wedge the
    // process until restart. Reset so the next call retries.
    this.initialization ??= this.initialize().catch(error => {
      this.initialization = undefined
      throw error
    })
    return this.initialization
  }

  public async createRequest(
    policyId: string,
    queryLanguage: OpenId4VcQueryLanguage = 'dcql',
    requestSigner?: 'x5c' | 'did',
  ): Promise<OpenId4VcVerificationRequest> {
    await this.ensureInitialized()

    const policy = findVerifierPolicy(this.options, policyId)
    if (!policy) {
      throw new OpenId4VcVerifierRequestError(`unknown verifier policy '${policyId}'`)
    }
    const configuration = findCredentialConfiguration(this.options, policy.credentialConfigurationId)
    if (!configuration) {
      throw new OpenId4VcVerifierRequestError(
        `verifier policy '${policyId}' references an unknown credential configuration`,
      )
    }

    const { authorizationRequest, verificationSession } = await this.verifierApi().createAuthorizationRequest(
      {
        verifierId: this.verifierOptions().id,
        requestSigner: await this.buildRequestSigner(queryLanguage, requestSigner),
        // JARM (direct_post.jwt) is DCQL-only: Presentation Exchange wallets can't build the JWE it needs.
        responseMode: queryLanguage === 'presentation_exchange' ? 'direct_post' : 'direct_post.jwt',
        ...presentationQueryFor(configuration, policy, queryLanguage),
      },
    )

    return {
      authorizationRequest,
      verificationSessionId: verificationSession.id,
    }
  }

  /** Public signing-certificate material, for operators wiring verifier
   *  fingerprint pins (never includes private keys). */
  public getCertificateInfo(): SigningCertificateInfo {
    return signingCertificateInfo('verifier', this.signingCertificateHandle())
  }

  public async getResult(sessionId: string): Promise<OpenId4VcVerificationResult> {
    const session = await this.getSession(sessionId)
    this.assertSessionOwnership(session, sessionId)

    if (session.state !== OpenId4VcVerificationSessionState.ResponseVerified) {
      return { state: session.state, cryptographicVerified: false, accepted: false }
    }

    const verified = await this.getVerifiedResponse(sessionId)
    this.assertStableVerifiedSession(verified, sessionId)

    const decision = await decidePresentation({
      agent: this.agent,
      options: this.options,
      trust: this.trustOptions(),
      trustClient: this.trustClient,
      verified,
    })
    return { state: session.state, ...decision }
  }

  private async initialize(): Promise<void> {
    const agentDid = this.agent.did
    if (!agentDid) throw new Error('OpenID4VC verifier initialization requires an agent DID')

    const signingCertificate = await loadSigningCertificate(
      this.agent,
      this.verifierOptions().signing,
      this.options.publicApiBaseUrl,
      'verifier',
    )
    const certificateDid = didFromValidatedCertificate(signingCertificate.certificate)
    if (certificateDid !== agentDid) {
      throw new Error('OpenID4VC verifier certificate DID does not match the agent DID')
    }
    await publishDevelopmentSigningKey(this.agent, signingCertificate, 'verifier')

    this.parallelWebSigningDidUrl = await publishParallelWebSigningKey(
      this.agent,
      this.trustOptions().timeoutMs,
    )

    const binding = await verifyKeyBoundToDid(
      this.agent,
      agentDid,
      signingCertificate.certificate.publicJwk.toJson(),
      ['authentication'],
      ownDidResolutionPolicy(agentDid, this.trustOptions().timeoutMs),
    )
    if (binding === 'unresolvable') {
      throw new Error('OpenID4VC verifier DID could not be resolved for authentication key binding')
    }
    if (binding !== 'bound') {
      throw new Error('OpenID4VC verifier certificate key is not bound to the agent DID authentication')
    }

    await this.createOrUpdateVerifier()
    this.signingCertificate = signingCertificate
    this.initialized = true
  }

  private async createOrUpdateVerifier(): Promise<void> {
    const verifier = this.verifierOptions()
    const metadata = {
      verifierId: verifier.id,
      clientMetadata: { client_name: verifier.displayName },
    }

    try {
      await this.verifierApi().getVerifierByVerifierId(verifier.id)
    } catch (error) {
      if (!(error instanceof RecordNotFoundError)) throw error
      await this.verifierApi().createVerifier(metadata)
      return
    }

    await this.verifierApi().updateVerifierMetadata(metadata)
  }

  private async getSession(sessionId: string): Promise<OpenId4VcVerificationSessionRecord> {
    try {
      return await this.verifierApi().getVerificationSessionById(sessionId)
    } catch (error) {
      if (error instanceof RecordNotFoundError) {
        throw new UnknownVerificationSessionError(
          `OpenID4VC verification session '${sessionId}' was not found`,
        )
      }
      throw error
    }
  }

  private async getVerifiedResponse(sessionId: string): Promise<OpenId4VpVerifiedAuthorizationResponse> {
    try {
      return await this.verifierApi().getVerifiedAuthorizationResponse(sessionId)
    } catch (error) {
      if (error instanceof RecordNotFoundError) {
        throw new UnknownVerificationSessionError(
          `OpenID4VC verification session '${sessionId}' was not found`,
        )
      }
      throw error
    }
  }

  private assertSessionOwnership(session: OpenId4VcVerificationSessionRecord, sessionId: string): void {
    if (session.verifierId !== this.verifierOptions().id) {
      throw new UnknownVerificationSessionError(`OpenID4VC verification session '${sessionId}' was not found`)
    }
  }

  private assertStableVerifiedSession(
    verified: OpenId4VpVerifiedAuthorizationResponse,
    sessionId: string,
  ): void {
    if (
      verified.verificationSession.id !== sessionId ||
      verified.verificationSession.verifierId !== this.verifierOptions().id ||
      verified.verificationSession.state !== OpenId4VcVerificationSessionState.ResponseVerified
    ) {
      throw new Error('OpenID4VC verification session changed while reading its verified result')
    }
  }

  private verifierApi(): VerifierApi {
    const verifier = this.agent.modules.openId4Vc?.verifier
    if (!verifier) throw new Error('OpenID4VC verifier API is not enabled on this agent')
    return verifier
  }

  private verifierOptions(): NonNullable<OpenId4VcPluginOptions['verifier']> {
    const verifier = this.options.verifier
    if (!verifier) throw new Error('OpenID4VC verifier capability is not configured')
    return verifier
  }

  private trustOptions(): NonNullable<OpenId4VcPluginOptions['trust']> {
    const trust = this.options.trust
    if (!trust) throw new Error('OpenID4VC verifier requires trust configuration')
    return trust
  }

  private signingCertificateHandle(): SigningCertificateHandle {
    if (!this.initialized || !this.signingCertificate) {
      throw new Error('OpenID4VC verifier service is not initialized')
    }
    return this.signingCertificate
  }

  private async buildRequestSigner(queryLanguage: OpenId4VcQueryLanguage, override?: 'x5c' | 'did') {
    const certificate = this.signingCertificateHandle()
    if ((override ?? this.verifierOptions().requestSigner) !== 'did') {
      return { method: 'x5c' as const, x5c: certificate.chain, clientIdPrefix: 'x509_hash' as const }
    }

    const did = this.agent.did ?? null

    // Presentation Exchange is the rail for wallets predating DCQL, and those wallets tend to
    // verify the request with an EdDSA-only implementation that resolves did:web but not
    // did:webvh. Sign that rail with the Ed25519 authentication key, named by the parallel
    // did:web the agent already publishes, so such a wallet can fetch the key and check the
    // signature. DCQL keeps the certificate-bound key and the did:webvh identifier, so the
    // wallets already verified against it are untouched.
    if (queryLanguage === 'presentation_exchange') {
      if (this.parallelWebSigningDidUrl) {
        return { method: 'did' as const, didUrl: this.parallelWebSigningDidUrl }
      }
      const ed25519DidUrl = await findEd25519VerificationMethodId(
        this.agent,
        did,
        ['authentication'],
        ownDidResolutionPolicy(did ?? '', this.trustOptions().timeoutMs),
      )
      if (ed25519DidUrl) return { method: 'did' as const, didUrl: ed25519DidUrl }
    }

    const didUrl = await findBoundVerificationMethodId(
      this.agent,
      did,
      certificate.certificate.publicJwk.toJson(),
      ['authentication'],
      ownDidResolutionPolicy(did ?? '', this.trustOptions().timeoutMs),
    )
    if (!didUrl) {
      throw new OpenId4VcVerifierRequestError(
        'verifier is configured to sign requests with its DID, but the DID does not publish the signing key for authentication',
      )
    }

    return { method: 'did' as const, didUrl }
  }
}
