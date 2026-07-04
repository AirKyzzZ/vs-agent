import type { X509Module } from '@credo-ts/core'
import type { OpenId4VcModule } from '@credo-ts/openid4vc'
import type { BaseAgentModules } from '@verana-labs/vs-agent-sdk'

export type OpenId4VcAgentModules = BaseAgentModules & {
  openId4Vc: OpenId4VcModule
  x509?: X509Module
}

export interface OpenId4VcPluginOptions {
  publicApiBaseUrl: string
  issuerEnabled: boolean
  verifierEnabled: boolean
  holderEnabled: boolean
  resolverUrl: string
  vct: string
  vtjscId: string
  rogueVerifierDid: string
}
