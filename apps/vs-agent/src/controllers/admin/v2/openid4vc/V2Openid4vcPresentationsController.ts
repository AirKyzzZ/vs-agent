import { Controller } from '@nestjs/common'
import { ApiTags } from '@nestjs/swagger'

/** [VSA-ADM-OID-PR] Presentations of the OpenID4VC verifier capability. */
@ApiTags('v2/openid4vc')
@Controller({ path: 'openid4vc', version: '2' })
export class V2Openid4vcPresentationsController {}
