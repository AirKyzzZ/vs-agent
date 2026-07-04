import type { OpenId4VcPluginOptions } from '../types'
import type { VsAgent, VsAgentNestPlugin } from '@verana-labs/vs-agent-sdk'

import { setupOpenId4Vc } from '../sdk/setupOpenId4Vc'
import { IssuerService } from '../services/IssuerService'
import { VerifierService } from '../services/VerifierService'
import { WalletService } from '../services/WalletService'

import { IssuerController, VctController } from './IssuerController'
import { VerifierController } from './VerifierController'
import { WalletController } from './WalletController'

export const OpenId4VcPlugin = (options: OpenId4VcPluginOptions): VsAgentNestPlugin => {
  let issuerService: IssuerService | undefined
  let verifierService: VerifierService | undefined
  let walletService: WalletService | undefined
  return {
    name: 'openid4vc',
    credoPlugin: setupOpenId4Vc(options),
    providers: [
      {
        provide: IssuerService,
        useFactory: (agent: VsAgent) => (issuerService ??= new IssuerService(agent, options)),
        inject: ['VSAGENT'],
      },
      {
        provide: VerifierService,
        useFactory: (agent: VsAgent) => (verifierService ??= new VerifierService(agent, options)),
        inject: ['VSAGENT'],
      },
      {
        provide: WalletService,
        useFactory: (agent: VsAgent) => (walletService ??= new WalletService(agent, options)),
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
        void (issuerService ??= new IssuerService(agent, options))
          .ensureInitialized()
          .catch(error => logger.error(`could not initialize OID4VCI issuer: ${error}`))
      }
      if (options.verifierEnabled) {
        void (verifierService ??= new VerifierService(agent, options))
          .ensureInitialized()
          .catch(error => logger.error(`could not initialize OID4VP verifier: ${error}`))
      }
    },
  }
}
