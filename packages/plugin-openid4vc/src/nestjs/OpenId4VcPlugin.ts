import type { OpenId4VcPluginOptions } from '../types'
import type { VsAgentNestPlugin } from '@verana-labs/vs-agent-sdk'

import { setupOpenId4Vc } from '../sdk/setupOpenId4Vc'

export const OpenId4VcPlugin = (options: OpenId4VcPluginOptions): VsAgentNestPlugin => ({
  name: 'openid4vc',
  credoPlugin: setupOpenId4Vc(options),
})
