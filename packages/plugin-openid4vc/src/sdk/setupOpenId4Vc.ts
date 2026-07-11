import type { OpenId4VcPluginOptions } from '../types'

import { X509Module } from '@credo-ts/core'
import { OpenId4VcModule, type OpenId4VcModuleConfigOptions } from '@credo-ts/openid4vc'
import express, { type Express, type NextFunction, type Request, type Response } from 'express'

import { buildCredentialRequestToCredentialMapper, getIssuerSigningJwk } from '../services/IssuerService'

let app: Express | undefined

export function getOpenId4VcExpressApp(): Express {
  app ??= express()
  return app
}

const OAUTH_AS_METADATA_PATH_PREFIX = '/.well-known/oauth-authorization-server'

// Credo exposes no hook to advertise attestation-based client auth; EUDI wallets pre-flight
// on client_attestation_pop_signing_alg_values_supported, so overlay it onto Credo's AS metadata.
const CLIENT_ATTESTATION_METADATA: Record<string, string[]> = {
  token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
  client_attestation_signing_alg_values_supported: ['ES256'],
  client_attestation_pop_signing_alg_values_supported: ['ES256'],
}

export function withClientAttestationMetadata(jsonBody: string): string {
  try {
    const metadata = JSON.parse(jsonBody)
    if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) return jsonBody
    for (const [field, values] of Object.entries(CLIENT_ATTESTATION_METADATA)) {
      const existing: unknown[] = Array.isArray(metadata[field]) ? metadata[field] : []
      for (const value of values) if (!existing.includes(value)) existing.push(value)
      metadata[field] = existing
    }
    return JSON.stringify(metadata)
  } catch {
    return jsonBody
  }
}

export function advertiseClientAttestationMetadata(req: Request, res: Response, next: NextFunction): void {
  if (req.method !== 'GET' || !req.path.startsWith(OAUTH_AS_METADATA_PATH_PREFIX)) {
    next()
    return
  }
  const originalSend = res.send.bind(res)
  res.send = ((body?: unknown) =>
    originalSend(typeof body === 'string' ? withClientAttestationMetadata(body) : body)) as Response['send']
  next()
}

export interface OpenId4VcSdkPlugin {
  modules: { openId4Vc: OpenId4VcModule; x509?: X509Module }
}

export function setupOpenId4Vc(
  options: OpenId4VcPluginOptions,
  app: Express = getOpenId4VcExpressApp(),
): OpenId4VcSdkPlugin {
  const config: OpenId4VcModuleConfigOptions = {
    app,
  }

  if (options.issuerEnabled) {
    app.use(advertiseClientAttestationMetadata)
    app.get('/.well-known/jwt-vc-issuer', (_req: Request, res: Response) => {
      const jwk = getIssuerSigningJwk()
      if (!jwk) {
        res.status(404).json({ error: 'issuer signing key not initialized' })
        return
      }
      res.json({ issuer: options.publicApiBaseUrl, jwks: { keys: [jwk] } })
    })
    config.issuer = {
      baseUrl: `${options.publicApiBaseUrl}/oid4vci`,
      credentialRequestToCredentialMapper: buildCredentialRequestToCredentialMapper(options),
    }
  }

  if (options.verifierEnabled) {
    config.verifier = { baseUrl: `${options.publicApiBaseUrl}/oid4vp` }
  }

  return {
    modules: {
      openId4Vc: new OpenId4VcModule(config),
      ...(options.holderEnabled || options.verifierEnabled || options.issuerEnabled
        ? {
            x509: new X509Module({
              getTrustedCertificatesForVerification: (_agentContext, { certificateChain, verification }) =>
                verification.type === 'oauth2SecuredAuthorizationRequest' ||
                verification.type === 'credential' ||
                verification.type === 'oauth2ClientAttestation'
                  ? certificateChain.map(certificate => certificate.toString('base64'))
                  : undefined,
            }),
          }
        : {}),
    },
  }
}
