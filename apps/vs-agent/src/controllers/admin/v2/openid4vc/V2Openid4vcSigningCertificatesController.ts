import { Controller } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'

/** [VSA-ADM-OID-CS] Signing certificates of the configured OpenID4VC capabilities. */
@ApiTags('v2/openid4vc')
@Controller({ path: 'openid4vc', version: '2' })
export class V2Openid4vcSigningCertificatesController {}
