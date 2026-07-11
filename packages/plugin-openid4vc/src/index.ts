export { setupOpenId4Vc, getOpenId4VcExpressApp } from './sdk/setupOpenId4Vc'
export type { OpenId4VcSdkPlugin } from './sdk/setupOpenId4Vc'
export { OpenId4VcPlugin } from './nestjs/OpenId4VcPlugin'
export { IssuerController, VctController } from './nestjs/IssuerController'
export { VerifierController } from './nestjs/VerifierController'
export { WalletController } from './nestjs/WalletController'
export {
  IssuerService,
  buildCredentialRequestToCredentialMapper,
  buildSdJwtPayload,
  getIssuerSigningJwk,
  resolveIssuerId,
} from './services/IssuerService'
export { VerifierService, UnknownSessionError } from './services/VerifierService'
export { buildReceipt } from './services/receipt'
export type { ProofOfTrustReceipt, ReceiptInput, ReceiptRegistry, PartyResult } from './services/receipt'
export {
  WalletService,
  GateBlockedError,
  ShareSubmissionError,
  extractRequestedVct,
} from './services/WalletService'
export { GateStore } from './services/GateStore'
export type { GateEntry } from './services/GateStore'
export { ensureP256CertificateWithDidSan, didFromCertificateSan } from './services/AgentSetup'
export type { CertificateHandle } from './services/AgentSetup'
export {
  DEFAULT_SD_JWT_VC_FORMAT,
  findConfigurationByVct,
  findCredentialConfiguration,
  parseOfferClaims,
  resolveDisclosureFrame,
  resolveFormat,
  validateCredentialConfigurations,
} from './config'
export type {
  OpenId4VcAgentModules,
  OpenId4VcCredentialConfiguration,
  OpenId4VcCredentialDisplay,
  OpenId4VcPluginOptions,
  OpenId4VcRegistryReference,
  SdJwtVcFormat,
} from './types'
export { TrustClient } from './trust/TrustClient'
export { computeVerdict } from './trust/verdict'
export type { Verdict, Q1Result, TrustEvidence, TrustVerdict } from './trust/types'
export { verifyKeyBoundToDid, blockingBindingVerdict, canonicalPublicKey } from './trust/keyBinding'
export type { KeyBindingResult, VerificationRelationship } from './trust/keyBinding'
