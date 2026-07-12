import type { X509Module } from '@credo-ts/core'
import type { OpenId4VcModule } from '@credo-ts/openid4vc'
import type { BaseAgentModules } from '@verana-labs/vs-agent-sdk'

export type OpenId4VcAgentModules = BaseAgentModules & {
  openId4Vc: OpenId4VcModule
  x509?: X509Module
}

/**
 * SD-JWT VC media type. `dc+sd-jwt` is the HAIP/current-draft type; `vc+sd-jwt` is the
 * legacy type some wallets still require.
 */
export type SdJwtVcFormat = 'dc+sd-jwt' | 'vc+sd-jwt'

export interface OpenId4VcCredentialDisplay {
  name?: string
  locale?: string
  backgroundColor?: string
  textColor?: string
  logoUri?: string
}

/**
 * One credential type the agent can issue and/or request. Each ecosystem defines its own
 * vct, claims, disclosure frame and Verana trust reference.
 */
export interface OpenId4VcCredentialConfiguration {
  /** credential_configuration_id, e.g. 'org-attestation' */
  id: string
  /** SD-JWT VC type URI */
  vct: string
  /** issuance media type; defaults to 'dc+sd-jwt' (HAIP) */
  format?: SdJwtVcFormat
  /** display name; also served as VCT type metadata */
  name: string
  description?: string
  /** Verifiable Trust JSON Schema Credential id (URL form) used for Verana trust resolution */
  vtjscId: string
  /** claim names accepted at offer time and requested in the DCQL query */
  claims: string[]
  /** selectively disclosable claims; defaults to `claims` */
  disclosureFrame?: string[]
  display?: OpenId4VcCredentialDisplay
}

/** On-chain registry coordinates stamped into the Proof-of-Trust receipt. */
export interface OpenId4VcRegistryReference {
  network: string
  trustRegistry: number
  schema: number
}

/** Token Status List revocation (draft-ietf-oauth-status-list). Opt-in; off preserves current behavior. */
export interface OpenId4VcRevocationOptions {
  enabled: boolean
  /** number of entries in the status list; default 131072 */
  size?: number
}

export interface OpenId4VcPluginOptions {
  /** this agent's public base URL (issuer identifier, cert SAN) */
  publicApiBaseUrl: string
  issuerEnabled: boolean
  verifierEnabled: boolean
  holderEnabled: boolean
  /** Verana Trust Resolver base URL */
  resolverUrl: string
  /** credential types this agent issues/requests; non-empty when issuer or verifier is enabled */
  credentialConfigurations: OpenId4VcCredentialConfiguration[]
  /** OID4VCI issuer id; default 'issuer' */
  issuerId?: string
  /** OID4VP verifier id; default 'verifier' */
  verifierId?: string
  /** issuer display name and signing-certificate common name; default 'Issuer' */
  issuerDisplayName?: string
  /** verifier display name; default 'Verifier' */
  verifierDisplayName?: string
  /** registry coordinates for the receipt; if omitted, derived from the resolver evidence */
  registry?: OpenId4VcRegistryReference
  /** Token Status List revocation; if omitted or disabled, issued credentials carry no status */
  revocation?: OpenId4VcRevocationOptions
  /**
   * Issue the issuer/verifier signing certs from an internal root CA (non-self-signed leaf, HAIP §5.1)
   * instead of a self-signed cert. Opt-in; default self-signed. Changes the x5c wallets see, so
   * re-validate wallet interop before enabling in production.
   */
  certificateChain?: { enabled: boolean }
}
