import type { OpenId4VcPluginOptions } from '../types'

import { X509Module } from '@credo-ts/core'
import { OpenId4VcModule, type OpenId4VcModuleConfigOptions } from '@credo-ts/openid4vc'
import express, { type Express } from 'express'

import { buildCredentialRequestToCredentialMapper } from '../services/IssuerService'

let app: Express | undefined

export function getOpenId4VcExpressApp(): Express {
  app ??= express()
  return app
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
