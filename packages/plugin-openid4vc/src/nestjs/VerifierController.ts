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

import { UnknownSessionError, VerifierService, type Tenant } from '../services/VerifierService'

function parseTenant(body: unknown): Tenant {
  const tenant = (body as { tenant?: unknown })?.tenant
  if (tenant !== 'trusted' && tenant !== 'rogue') {
    throw new BadRequestException("tenant must be 'trusted' or 'rogue'")
  }
  return tenant
}

@Controller('oid4vc-demo/verifier')
export class VerifierController {
  public constructor(@Inject(VerifierService) private readonly verifierService: VerifierService) {}

  @Post('requests')
  public async createRequest(@Body() body: unknown) {
    const tenant = parseTenant(body)
    return await this.verifierService.createRequest(tenant)
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
