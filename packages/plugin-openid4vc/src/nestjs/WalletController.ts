import {
  BadGatewayException,
  BadRequestException,
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Inject,
  Post,
} from '@nestjs/common'

import { GateBlockedError, ShareSubmissionError, WalletService } from '../services/WalletService'

const MAX_URI_LENGTH = 10000

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim() || value.length > MAX_URI_LENGTH) {
    throw new BadRequestException(
      `${field} must be a non-empty string of at most ${MAX_URI_LENGTH} characters`,
    )
  }
  return value
}

@Controller('oid4vc-demo/wallet')
export class WalletController {
  public constructor(@Inject(WalletService) private readonly walletService: WalletService) {}

  @Post('accept-offer')
  public async acceptOffer(@Body() body: unknown) {
    const credentialOffer = requireString(
      (body as { credentialOffer?: unknown })?.credentialOffer,
      'credentialOffer',
    )
    return await this.walletService.acceptOffer(credentialOffer)
  }

  @Get('credentials')
  public async listCredentials() {
    return await this.walletService.listCredentials()
  }

  @Delete('credentials')
  public async clearCredentials() {
    await this.walletService.clearCredentials()
    return { cleared: true }
  }

  @Post('resolve-request')
  public async resolveRequest(@Body() body: unknown) {
    const authorizationRequest = requireString(
      (body as { authorizationRequest?: unknown })?.authorizationRequest,
      'authorizationRequest',
    )
    return await this.walletService.resolveRequest(authorizationRequest)
  }

  @Post('share')
  public async share(@Body() body: unknown) {
    const gateId = requireString((body as { gateId?: unknown })?.gateId, 'gateId')
    try {
      return await this.walletService.share(gateId)
    } catch (error) {
      if (error instanceof GateBlockedError) {
        throw new ForbiddenException({ shared: false, verdict: error.verdict, reason: error.reason })
      }
      if (error instanceof ShareSubmissionError) {
        throw new BadGatewayException({ shared: false, reason: error.message })
      }
      throw error
    }
  }
}
