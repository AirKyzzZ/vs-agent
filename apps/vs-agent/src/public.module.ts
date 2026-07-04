import { DynamicModule, Module } from '@nestjs/common'
import { VsAgent, VsAgentNestPlugin } from '@verana-labs/vs-agent-sdk'

import {
  CredentialTypesService,
  DidWebController,
  InvitationRoutesController,
  SelfTrController,
  TrustService,
} from './controllers'
import { UrlShorteningService } from './services'
import { VsAgentService } from './services/VsAgentService'

@Module({})
export class PublicModule {
  static register(
    agent: VsAgent,
    publicApiBaseUrl: string,
    nestPlugins: VsAgentNestPlugin[] = [],
  ): DynamicModule {
    const agentRef = { get: () => agent, toJSON: () => 'VsAgent' }
    return {
      module: PublicModule,
      imports: [],
      controllers: [
        InvitationRoutesController,
        SelfTrController,
        DidWebController,
        ...nestPlugins.flatMap(p => p.publicControllers ?? []),
      ],
      providers: [
        {
          provide: 'VSAGENT',
          useFactory: () => agentRef.get(),
        },
        {
          provide: 'PUBLIC_API_BASE_URL',
          useFactory: () => publicApiBaseUrl,
        },
        VsAgentService,
        TrustService,
        UrlShorteningService,
        CredentialTypesService,
        // Only plugins contributing public controllers bring their providers here.
        // Providers from admin-only plugins (e.g. messaging's MESSAGE_HANDLERS-dependent
        // MessageService) must not leak into this module, since their required tokens
        // are only registered in VsAgentModule (the admin module).
        ...nestPlugins.filter(p => (p.publicControllers?.length ?? 0) > 0).flatMap(p => p.providers ?? []),
      ],
      exports: [],
    }
  }
}
