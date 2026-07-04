import { BadRequestException, Body, Controller, Get, Inject, Param, Post } from '@nestjs/common'

import { parseOfferClaims, IssuerService } from '../services/IssuerService'

@Controller('oid4vc-demo/offers')
export class IssuerController {
  public constructor(@Inject(IssuerService) private readonly issuerService: IssuerService) {}

  @Post()
  public async createOffer(@Body() body: unknown) {
    let claims: { organization: string; role: string }
    try {
      claims = parseOfferClaims(body)
    } catch (error) {
      throw new BadRequestException(error instanceof Error ? error.message : 'invalid claims')
    }
    return await this.issuerService.createOffer(claims)
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
