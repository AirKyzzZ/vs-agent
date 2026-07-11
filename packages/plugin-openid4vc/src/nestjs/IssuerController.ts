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

import { IssuerService } from '../services/IssuerService'

@Controller('oid4vc/offers')
export class IssuerController {
  public constructor(@Inject(IssuerService) private readonly issuerService: IssuerService) {}

  @Post()
  public async createOffer(@Body() body: unknown) {
    const { credentialConfigurationId, claims, externalWallet } = (body ?? {}) as {
      credentialConfigurationId?: unknown
      claims?: unknown
      externalWallet?: unknown
    }
    if (typeof credentialConfigurationId !== 'string' || !credentialConfigurationId.trim()) {
      throw new BadRequestException('credentialConfigurationId is required')
    }
    if (externalWallet !== undefined && typeof externalWallet !== 'boolean') {
      throw new BadRequestException('externalWallet must be a boolean')
    }
    try {
      return await this.issuerService.createOffer(credentialConfigurationId, claims, {
        requireWalletAttestation: externalWallet === true,
      })
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : 'invalid offer')
    }
  }

  @Get(':id')
  public async getOffer(@Param('id') id: string) {
    return await this.issuerService.getOfferState(id)
  }
}

@Controller('vct')
export class VctController {
  public constructor(@Inject(IssuerService) private readonly issuerService: IssuerService) {}

  @Get(':id')
  public getVct(@Param('id') id: string) {
    const metadata = this.issuerService.getVctMetadata(id)
    if (!metadata) throw new NotFoundException(`unknown credential type '${id}'`)
    return metadata
  }
}
