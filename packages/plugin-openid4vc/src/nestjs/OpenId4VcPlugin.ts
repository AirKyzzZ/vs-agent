import type { OpenId4VcAgentModules, OpenId4VcPluginOptions } from '../types'
import type { VsAgent, VsAgentNestPlugin } from '@verana-labs/vs-agent-sdk'

import { validateCredentialConfigurations } from '../config'
import { setupOpenId4Vc } from '../sdk/setupOpenId4Vc'
import { IssuerService } from '../services/IssuerService'
import { VerifierService } from '../services/VerifierService'
import { WalletService } from '../services/WalletService'

import { IssuerController, VctController } from './IssuerController'
import { VerifierController } from './VerifierController'
import { WalletController } from './WalletController'

export const OpenId4VcPlugin = (options: OpenId4VcPluginOptions): VsAgentNestPlugin => {
  if (options.issuerEnabled || options.verifierEnabled) {
    validateCredentialConfigurations(options.credentialConfigurations)
  }

  let issuerService: IssuerService | undefined
  let verifierService: VerifierService | undefined
  let walletService: WalletService | undefined

  const asOpenId4VcAgent = (agent: VsAgent) => agent as VsAgent<OpenId4VcAgentModules>

  return {
    name: 'openid4vc',
    credoPlugin: setupOpenId4Vc(options),
    providers: [
      {
        provide: IssuerService,
        useFactory: (agent: VsAgent) =>
          (issuerService ??= new IssuerService(asOpenId4VcAgent(agent), options)),
        inject: ['VSAGENT'],
      },
      {
        provide: VerifierService,
        useFactory: (agent: VsAgent) =>
          (verifierService ??= new VerifierService(asOpenId4VcAgent(agent), options)),
        inject: ['VSAGENT'],
      },
      {
        provide: WalletService,
        useFactory: (agent: VsAgent) =>
          (walletService ??= new WalletService(asOpenId4VcAgent(agent), options)),
        inject: ['VSAGENT'],
      },
    ],
    publicControllers: [
      ...(options.issuerEnabled ? [IssuerController, VctController] : []),
      ...(options.verifierEnabled ? [VerifierController] : []),
      ...(options.holderEnabled ? [WalletController] : []),
    ],
    registerEvents: (agent, logger) => {
      if (options.issuerEnabled) {
        void (issuerService ??= new IssuerService(asOpenId4VcAgent(agent), options))
          .ensureInitialized()
          .catch(error => logger.error(`could not initialize OID4VCI issuer: ${error}`))
      }
      if (options.verifierEnabled) {
        void (verifierService ??= new VerifierService(asOpenId4VcAgent(agent), options))
          .ensureInitialized()
          .catch(error => logger.error(`could not initialize OID4VP verifier: ${error}`))
      }
    },
  }
}
