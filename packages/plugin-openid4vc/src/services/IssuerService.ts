import type { OpenId4VcPluginOptions } from '../types'
import type { OpenId4VciCredentialRequestToCredentialMapper } from '@credo-ts/openid4vc'

export function buildCredentialRequestToCredentialMapper(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _options: OpenId4VcPluginOptions,
): OpenId4VciCredentialRequestToCredentialMapper {
  return () => {
    throw new Error('credential issuance not configured yet')
  }
}
