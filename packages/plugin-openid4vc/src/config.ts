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
  for (const config of configs) {
    if (!config.id?.trim()) throw new Error('every credential configuration needs a non-empty id')
    if (ids.has(config.id)) throw new Error(`duplicate credential configuration id '${config.id}'`)
    ids.add(config.id)
    if (!config.name?.trim()) throw new Error(`credential configuration '${config.id}': name is required`)
    assertHttpUrl(config.vct, 'vct', config.id)
    assertHttpUrl(config.vtjscId, 'vtjscId', config.id)
    if (!Array.isArray(config.claims) || config.claims.length === 0) {
      throw new Error(`credential configuration '${config.id}': claims must be a non-empty array`)
    }
    if (config.disclosureFrame?.some(claim => !config.claims.includes(claim))) {
      throw new Error(`credential configuration '${config.id}': disclosureFrame must be a subset of claims`)
    }
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
