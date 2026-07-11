import {
  BadRequestException,
  Body,
  Controller,
  Get,
  Inject,
  NotFoundException,
  Param,
  Post,
} from '@nestjs/common'

import { UnknownSessionError, VerifierService } from '../services/VerifierService'

@Controller('oid4vc/verifier')
export class VerifierController {
  public constructor(@Inject(VerifierService) private readonly verifierService: VerifierService) {}

  @Post('requests')
  public async createRequest(@Body() body: unknown) {
    const credentialConfigurationId = (body as { credentialConfigurationId?: unknown })
      ?.credentialConfigurationId
    if (credentialConfigurationId !== undefined && typeof credentialConfigurationId !== 'string') {
      throw new BadRequestException('credentialConfigurationId must be a string')
    }
    try {
      return await this.verifierService.createRequest(credentialConfigurationId)
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : 'invalid request')
    }
  }

  @Get('sessions/:id')
  public async getSession(@Param('id') id: string) {
    try {
      return await this.verifierService.getSession(id)
    } catch (error) {
      if (error instanceof UnknownSessionError) throw new NotFoundException(error.message)
      throw error
    }
  }
}
