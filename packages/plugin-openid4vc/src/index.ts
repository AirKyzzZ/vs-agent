export { setupOpenId4Vc, getOpenId4VcExpressApp } from './sdk/setupOpenId4Vc'
export type { OpenId4VcSdkPlugin } from './sdk/setupOpenId4Vc'
export { OpenId4VcPlugin } from './nestjs/OpenId4VcPlugin'
export { IssuerController, VctController } from './nestjs/IssuerController'
export {
  IssuerService,
  buildCredentialRequestToCredentialMapper,
  buildSdJwtPayload,
  CREDENTIAL_CONFIGURATION_ID,
  DISCLOSURE_FRAME,
  ISSUER_ID,
} from './services/IssuerService'
export { ensureP256CertificateWithDidSan } from './services/AgentSetup'
export type { CertificateHandle } from './services/AgentSetup'
export type { OpenId4VcAgentModules, OpenId4VcPluginOptions } from './types'
export { TrustClient } from './trust/TrustClient'
export { computeVerdict } from './trust/verdict'
export type { Verdict, Q1Result, TrustEvidence, TrustVerdict } from './trust/types'
