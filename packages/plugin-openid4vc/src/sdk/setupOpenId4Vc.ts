import type { OpenId4VcPluginOptions } from '../types'

import { OpenId4VcModule, type OpenId4VcModuleConfigOptions } from '@credo-ts/openid4vc'
import express, { type Express } from 'express'

import { buildCredentialRequestToCredentialMapper } from '../services/IssuerService'

let app: Express | undefined

export function getOpenId4VcExpressApp(): Express {
  app ??= express()
  return app
}

export interface OpenId4VcSdkPlugin {
  modules: { openId4Vc: OpenId4VcModule }
}

export function setupOpenId4Vc(options: OpenId4VcPluginOptions): OpenId4VcSdkPlugin {
  const config: OpenId4VcModuleConfigOptions = {
    app: getOpenId4VcExpressApp(),
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
    },
  }
}
