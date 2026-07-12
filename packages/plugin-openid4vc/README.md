# @verana-labs/vs-agent-plugin-openid4vc

A [vs-agent](https://github.com/verana-labs/vs-agent) plugin that runs **OpenID4VCI** issuance and **OpenID4VP 1.0** verification with a live, fail-closed **Verana trust check woven into the exchange**.

Built on Credo-TS `@credo-ts/openid4vc`. It powers the France Identité EUDI "Unfold" playground, where an issuer, a verifier, and Verana (as the trust registry vouching for both) run a real EU-style credential lifecycle on testnet.

## Why this exists

Every credential exchange asks two independent questions:

1. Is the data **cryptographically valid**? (signature, integrity, expiry, revocation)
2. Should you actually **trust the parties**? (is the issuer accredited to issue this? is the verifier authorized to request it?)

OpenID4VCI and OpenID4VP only answer #1. A valid signature from an unknown or unaccredited party still passes. This plugin answers #2, live and on-chain, at the two moments in the flow where it matters. It is the step eIDAS 2 requires (relying parties must be registered and authorized for exactly what they request) and the base EUDI stack leaves open.

## Architecture

Three layers:

- **`@credo-ts/openid4vc`** — the protocol engine (offers, credential requests, DCQL matching, `direct_post.jwt`, status lists). The plugin drives it, it does not reimplement it.
- **`vs-agent`** — the NestJS host: DID management, HTTP, multi-role agents.
- **this plugin** — the glue plus the Verana brain: the trust client, the DID↔key binding check, the fail-closed consent gate, and the REST surface.

Three roles, toggled by config (`issuerEnabled` / `verifierEnabled` / `holderEnabled`), typically deployed as three agents:

- **Issuer** — runs OID4VCI, mints an SD-JWT VC.
- **Wallet (holder)** — holds the credential and hosts the consent gate. Verify-the-verifier happens here, before anything is disclosed.
- **Verifier** — runs OID4VP, requests the credential, and checks the issuer after cryptographic verification passes.

Everything is driven by a list of **credential configurations** (`credentialConfigurations[]`) — one entry per credential type, each with its own `vct`, claims, disclosure frame, display and Verana schema reference (`vtjscId`). No ecosystem-specific constants are baked in.

## End-to-end flow

**Issuance (OID4VCI, pre-authorized code)**
1. Issuer `createOffer(credentialConfigurationId, claims)` builds a pre-auth offer. Format is SD-JWT VC (`dc+sd-jwt` by default); the configured claims are selectively disclosable.
2. `buildCredentialRequestToCredentialMapper` signs the credential with an x5c chain (`alg ES256`). The signing key is also published in the issuer's DID document. If revocation is enabled, a `status.status_list` entry is allocated and embedded.
3. Wallet accepts and holds the SD-JWT VC.

**Presentation (OID4VP 1.0)**
4. Verifier `createRequest(credentialConfigurationId?)` builds a DCQL query for the `vct` and claims, signed x5c, `clientIdPrefix: x509_hash`, `responseMode: direct_post.jwt` (Credo encrypts the response by default — ECDH-ES P-256, A128/256GCM).
5. **[Verana hook #1, verify the verifier]** Wallet `resolveRequest` extracts the verifier DID from the request cert's SAN, **verifies the request-signing key is bound to that DID document** (fail-closed), then asks Verana `verdictFor('verifier', did, vtjscId)`. It stores the verdict and the disclosure in a `GateStore` behind a fresh UUID, and returns only the verdict. The disclosure never leaves this call.
6. **[the fail-closed gate]** Wallet `share(gateId)`: if the stored verdict is not exactly `TRUSTED_AUTHORIZED`, it throws `GateBlockedError` (HTTP 403) before Credo discloses anything. The gate is single-use.
7. **[Verana hook #2, verify the issuer]** Verifier `getSession` runs trust logic only once Credo reports `ResponseVerified` (crypto + revocation done). It extracts the issuer DID from the presented credential's cert SAN, **verifies the credential's signing key is bound to that DID document**, then asks `verdictFor('issuer', did, vtjscId)`.
8. Both verdicts plus the on-chain evidence (and `credentialStatus` when a status list was in play) are assembled into a `ProofOfTrustReceipt`.

## Trust: DID↔key binding + the Verana verdict

The certificate is a **key carrier, not a trust anchor**. Trust is decided by the DID and the Verana registry, so before any registry lookup the plugin authenticates the DID→signing-key binding:

- **`trust/keyBinding.ts`** — `verifyKeyBoundToDid(agent, did, signingKeyJwk, relationships)` resolves the asserted DID document and requires the exact signing key to be a verification method (`assertionMethod` for issuers, `authentication`/`assertionMethod` for verifiers). It is **fail-closed**: an unresolvable DID → `RESOLVER_UNAVAILABLE`, a key that is not in the document → `UNTRUSTED`. A self-signed cert asserting someone else's DID in its SAN fails here and never reaches Verana.

- **`trust/TrustClient`** — `resolve(did)` (Q1: is the DID a trusted Verifiable Service?), `checkAuthorization(role, did, vtjscId)` (Q2 = issuer-authorization, Q3 = verifier-authorization), and `verdictFor(role, did, vtjscId)` which composes them.

- **`trust/verdict.ts` `computeVerdict`** — never fails open:
  - resolver unreachable → `RESOLVER_UNAVAILABLE` (blocks)
  - DID not found / not `TRUSTED` → `UNTRUSTED` (blocks)
  - `TRUSTED` but authorization fails/unreachable → `RESOLVER_UNAVAILABLE` (blocks)
  - `TRUSTED` + `authorized:true` → `TRUSTED_AUTHORIZED` (the only pass)
  - `TRUSTED` + `authorized:false` → `TRUSTED_NOT_AUTHORIZED` (blocks)

Important: `vtjscId` must be the **VTJSC URL** (e.g. `https://<issuer>/vt/schemas-<name>-jsc.json`), not the `vpr:` schema reference. The resolver keys authorization on the URL form.

## EU-norm conformance (HAIP 1.0)

Targets the **OpenID4VC High Assurance Interoperability Profile 1.0** as the interop baseline (SD-JWT VC draft-17, Token Status List draft-21, eIDAS 2 / ARF v2.9.0).

Satisfied:
- **`dc+sd-jwt`, ES256, DCQL, `direct_post.jwt`** with response encryption (Credo generates the JARM ECDH-ES key and enforces an encrypted response).
- **Wallet (client) attestation** advertised and accepted (see interoperability below).
- **VCT Type Metadata** (`display` + per-claim descriptors) served at `/vct/:id` so wallets render a real card instead of a generic fallback.
- **Non-self-signed x5c** available via an opt-in internal CA (`certificateChain`).
- **Token Status List** revocation, opt-in (below).

Deliberately out of scope / follow-up (documented, not built): mdoc/mDL, Article 22 Trusted List inclusion, formal EU PKI participation (ACA-issued access certificate, LoTL anchoring — org-level, mid-2026+ infra), the `authorization_code` grant end-to-end (Credo advertises it but a working flow needs an external AS or presentation-during-issuance), and issuer-required key attestation (an ecosystem policy choice, not a blanket MUST for a non-qualified EAA).

## Revocation (Token Status List)

Opt-in via `revocation: { enabled: true, size? }` (default off — issued credentials carry no status). When enabled:

- The issuer maintains one signed status list (`StatusListService`, backed by Credo's `TokenStatusListApi` and `@owf/token-status-list`), allocates a 1-bit entry per issued credential, and embeds `status.status_list.{idx,uri}` in the SD-JWT.
- The signed token is served at **`GET /oid4vc/status-list/:id`** (`Content-Type: application/statuslist+jwt`).
- The verifier check is **automatic and fail-closed**: Credo's SD-JWT VC verification fetches the list, validates its signature against the issuer's chain, and rejects a revoked credential before it ever reaches `ResponseVerified`. A verified presentation that carried a status reference surfaces `credential.credentialStatus: 'valid'` on the receipt.
- **`IssuerService.revoke(issuanceSessionId)`** flips the bit and re-signs (idempotent). No HTTP revoke endpoint is exposed — wire your own authenticated admin path around the service method.

Index allocation is serialized in-process; a horizontally scaled issuer would need a distributed allocator (out of scope, documented).

## Real-wallet interoperability

Validated end-to-end against the **EUDI reference wallet** (`eu-digital-identity-wallet/eudi-app-android-wallet-ui`): full OID4VCI issuance, including a real Wallet Unit Attestation the issuer accepts. Three behaviors bridge Credo to what real EU wallets require:

- **Issues `dc+sd-jwt`** (the renamed SD-JWT VC media type), with `vc+sd-jwt` available as a fallback credential configuration.
- **Advertises attestation-based client auth.** An issuer-only middleware (`advertiseClientAttestationMetadata`) overlays `client_attestation_pop_signing_alg_values_supported` (which EUDI wallet-core pre-flights on) onto Credo's `/.well-known/oauth-authorization-server` metadata.
- **Serves `/.well-known/jwt-vc-issuer`** with the issuer's signing JWKS, for SD-JWT VC issuer-key discovery.

Wallets enforce different policy on the same protocol; target the EUDI ARF / HAIP profile and serve the union of discovery endpoints. The Verana trust verdict is independent of all of this — a server-side resolver call, identical across wallets and formats.

> Note: enabling `certificateChain` changes the x5c wallets see; re-validate against the real EUDI wallet before enabling it in production. The default self-signed path is the validated one.

## Configuration

`OpenId4VcPluginOptions` (`src/types.ts`):

| Option | Purpose |
|---|---|
| `publicApiBaseUrl` | This agent's public base URL (issuer identifier, cert SAN) |
| `issuerEnabled` / `verifierEnabled` / `holderEnabled` | Role toggles |
| `resolverUrl` | Verana Trust Resolver base URL |
| `credentialConfigurations[]` | The credential types this agent issues/requests (required when issuer or verifier is enabled) |
| `issuerId` / `verifierId` | OID4VC issuer/verifier ids (default `issuer` / `verifier`) |
| `issuerDisplayName` / `verifierDisplayName` | Display name + signing-cert common name |
| `registry` | Registry coordinates stamped into the receipt (else derived from the resolver evidence) |
| `revocation` | `{ enabled, size? }` — Token Status List; default off |
| `certificateChain` | `{ enabled }` — issue the signing cert from an internal CA; default self-signed |

Each `OpenId4VcCredentialConfiguration`: `{ id, vct, format?, name, description?, vtjscId, claims[], disclosureFrame?, display? }`. The list is validated at boot (fail-fast on duplicate id, non-URL `vct`/`vtjscId`, empty/non-string claims, a `disclosureFrame` that is not a subset of `claims`, and duplicate `vct`+`format` pairs).

### App environment (`apps/vs-agent`)

| Env var | Maps to |
|---|---|
| `OID4VC_ISSUER_ENABLED` / `OID4VC_VERIFIER_ENABLED` / `OID4VC_HOLDER_ENABLED` | role toggles |
| `VERANA_RESOLVER_URL` | `resolverUrl` |
| `OID4VC_CREDENTIAL_CONFIGURATIONS` | `credentialConfigurations` (JSON array) |
| `OID4VC_ISSUER_ID` / `OID4VC_VERIFIER_ID` | ids |
| `OID4VC_ISSUER_DISPLAY_NAME` / `OID4VC_VERIFIER_DISPLAY_NAME` | display names |
| `OID4VC_REGISTRY` | `registry` (JSON) |
| `OID4VC_REVOCATION_ENABLED` / `OID4VC_REVOCATION_SIZE` | `revocation` |
| `OID4VC_CERTIFICATE_CHAIN_ENABLED` | `certificateChain` |

## REST API

Issuance
- `POST /oid4vc/offers` — `{ credentialConfigurationId, claims, externalWallet? }` → offer + `issuanceSessionId`
- `GET /oid4vc/offers/:id` — issuance session state
- `GET /vct/:id` — SD-JWT VC Type Metadata for a credential type
- `GET /oid4vc/status-list/:id` — signed status list token (when revocation is enabled)

Wallet (holder)
- `POST /oid4vc/wallet/accept-offer`, `GET|DELETE /oid4vc/wallet/credentials`
- `POST /oid4vc/wallet/resolve-request`, `POST /oid4vc/wallet/share`

Presentation (verifier)
- `POST /oid4vc/verifier/requests` — `{ credentialConfigurationId? }`
- `GET /oid4vc/verifier/sessions/:id` — session state + `ProofOfTrustReceipt`

## Source map

- `nestjs/OpenId4VcPlugin.ts` — plugin factory, wires services + controllers per role flags, validates config at boot
- `nestjs/{Issuer,Verifier,Wallet}Controller.ts` — the REST endpoints (`IssuerController` also serves `/vct/:id`)
- `config.ts` — credential-configuration validation, lookups, VCT Type Metadata, offer-claim parsing
- `services/IssuerService.ts` — OID4VCI issuance, SD-JWT mapper, x5c signing, `revoke`
- `services/VerifierService.ts` — OID4VP request, DCQL, post-crypto issuer check, receipt
- `services/WalletService.ts` — holder API, verify-the-verifier, the fail-closed gate
- `services/StatusListService.ts` — Token Status List state, allocation and re-signing
- `services/GateStore.ts` — single-use gate storage
- `services/receipt.ts` — the Proof-of-Trust receipt
- `services/AgentSetup.ts` — P-256 cert with DID-in-SAN (self-signed or internal-CA chain), `didFromCertificateSan`
- `sdk/setupOpenId4Vc.ts` — Credo module setup, Express mount, discovery + status-list routes
- `trust/` — `keyBinding`, `TrustClient`, `computeVerdict`, types

## Testing

`pnpm test` runs unit tests plus in-process integration tests that stand up real issuer/wallet/verifier agents over HTTP and exercise the full lifecycle: issue → hold → present → trust verdict, the rogue-verifier and spoofed-key blocks, resolver-down fail-closed, revocation (issue → present-valid → revoke → present-blocked), and the internal-CA chain end-to-end.
