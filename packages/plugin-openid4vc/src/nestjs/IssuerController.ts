import { BadRequestException, Body, Controller, Get, Inject, Param, Post } from '@nestjs/common'

import { IssuerService } from '../services/IssuerService'

@Controller('oid4vc-demo/offers')
export class IssuerController {
  public constructor(@Inject(IssuerService) private readonly issuerService: IssuerService) {}

  @Post()
  public async createOffer(@Body() body: { organization?: string; role?: string }) {
    if (!body?.organization || !body?.role)
      throw new BadRequestException('organization and role are required')
    return await this.issuerService.createOffer({ organization: body.organization, role: body.role })
  }

  @Get(':id')
  public async getOffer(@Param('id') id: string) {
    return await this.issuerService.getOfferState(id)
  }
}

@Controller('vct')
export class VctController {
  @Get('unfold-attestation')
  public getVct() {
    return {
      vct: 'https://unfold-org.77.42.86.24.sslip.io/vct/unfold-attestation',
      name: 'Unfold Attestation',
      description:
        'Non-qualified attestation for the Unfold demonstration ecosystem, anchored in Verana trust registry 184, schema 249',
    }
  }
}
