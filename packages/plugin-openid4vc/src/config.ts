import type { OpenId4VcCredentialConfiguration, SdJwtVcFormat } from './types'

export const DEFAULT_SD_JWT_VC_FORMAT: SdJwtVcFormat = 'dc+sd-jwt'
const MAX_CLAIM_LENGTH = 200

export function resolveFormat(config: OpenId4VcCredentialConfiguration): SdJwtVcFormat {
  return config.format ?? DEFAULT_SD_JWT_VC_FORMAT
}

export function resolveDisclosureFrame(config: OpenId4VcCredentialConfiguration): string[] {
  return config.disclosureFrame ?? config.claims
}

export function findCredentialConfiguration(
  configs: OpenId4VcCredentialConfiguration[],
  id: string,
): OpenId4VcCredentialConfiguration | undefined {
  return configs.find(config => config.id === id)
}

export function findConfigurationByVct(
  configs: OpenId4VcCredentialConfiguration[],
  vct: string,
): OpenId4VcCredentialConfiguration | undefined {
  return configs.find(config => config.vct === vct)
}

function assertHttpUrl(value: string, field: string, configId: string): void {
  let url: URL
  try {
    url = new URL(value)
  } catch {
    throw new Error(`credential configuration '${configId}': ${field} must be a valid URL`)
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`credential configuration '${configId}': ${field} must be an http(s) URL`)
  }
}

/** Validate the credential configuration list. Throws (fail-fast at boot) on any problem. */
export function validateCredentialConfigurations(configs: OpenId4VcCredentialConfiguration[]): void {
  if (!Array.isArray(configs) || configs.length === 0) {
    throw new Error('credentialConfigurations must be a non-empty array')
  }
  const ids = new Set<string>()
  const vctFormats = new Set<string>()
  for (const config of configs) {
    if (!config.id?.trim()) throw new Error('every credential configuration needs a non-empty id')
    if (ids.has(config.id)) throw new Error(`duplicate credential configuration id '${config.id}'`)
    ids.add(config.id)
    if (!config.name?.trim()) throw new Error(`credential configuration '${config.id}': name is required`)
    assertHttpUrl(config.vct, 'vct', config.id)
    assertHttpUrl(config.vtjscId, 'vtjscId', config.id)
    if (config.format && config.format !== 'dc+sd-jwt' && config.format !== 'vc+sd-jwt') {
      throw new Error(`credential configuration '${config.id}': format must be 'dc+sd-jwt' or 'vc+sd-jwt'`)
    }
    // the same vct may appear under different formats (dual-profile), but not twice for one format
    const vctFormat = `${config.vct}::${resolveFormat(config)}`
    if (vctFormats.has(vctFormat)) {
      throw new Error(
        `duplicate credential configuration for vct '${config.vct}' and format '${resolveFormat(config)}'`,
      )
    }
    vctFormats.add(vctFormat)
    if (!Array.isArray(config.claims) || config.claims.length === 0) {
      throw new Error(`credential configuration '${config.id}': claims must be a non-empty array`)
    }
    if (config.claims.some(claim => typeof claim !== 'string' || !claim.trim())) {
      throw new Error(`credential configuration '${config.id}': every claim must be a non-empty string`)
    }
    if (config.disclosureFrame?.some(claim => !config.claims.includes(claim))) {
      throw new Error(`credential configuration '${config.id}': disclosureFrame must be a subset of claims`)
    }
  }
}

/**
 * Build the SD-JWT VC Type Metadata document (draft-ietf-oauth-sd-jwt-vc, VCT metadata) served at
 * the credential's vct URL. Real wallets use `display` to render and `claims` for labels + selective
 * disclosure hints; a bare {vct,name,description} makes them fall back to a generic card.
 */
export function buildVctTypeMetadata(config: OpenId4VcCredentialConfiguration): Record<string, unknown> {
  const lang = config.display?.locale ?? 'en'
  const disclosable = new Set(resolveDisclosureFrame(config))
  const simple: Record<string, unknown> = {}
  if (config.display?.logoUri) simple.logo = { uri: config.display.logoUri }
  if (config.display?.backgroundColor) simple.background_color = config.display.backgroundColor
  if (config.display?.textColor) simple.text_color = config.display.textColor
  return {
    vct: config.vct,
    name: config.name,
    ...(config.description ? { description: config.description } : {}),
    display: [
      {
        lang,
        name: config.display?.name ?? config.name,
        ...(config.description ? { description: config.description } : {}),
        ...(Object.keys(simple).length > 0 ? { rendering: { simple } } : {}),
      },
    ],
    claims: config.claims.map(name => ({
      path: [name],
      display: [{ lang, label: name }],
      sd: disclosable.has(name) ? 'allowed' : 'never',
    })),
  }
}

/**
 * Validate the claims supplied at offer time against a credential configuration.
 * Every configured claim must be a non-empty string of at most 200 characters.
 */
export function parseOfferClaims(
  config: OpenId4VcCredentialConfiguration,
  input: unknown,
): Record<string, string> {
  const raw = (input ?? {}) as Record<string, unknown>
  const claims: Record<string, string> = {}
  for (const name of config.claims) {
    const value = raw[name]
    if (typeof value !== 'string' || !value.trim() || value.length > MAX_CLAIM_LENGTH) {
      throw new Error(`claim '${name}' must be a non-empty string of at most ${MAX_CLAIM_LENGTH} characters`)
    }
    claims[name] = value
  }
  return claims
}
