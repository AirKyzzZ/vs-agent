# @verana-labs/vs-agent-plugin-openid4vc

A [vs-agent](https://github.com/verana-labs/vs-agent) plugin that runs **OpenID4VCI** issuance and **OpenID4VP 1.0** verification with a live, fail-closed **Verana trust check woven into the exchange**.

Built on Credo-TS `@credo-ts/openid4vc`. It powers the France Identité EUDI "Unfold" playground, where an issuer, a verifier, and Verana (as the trust registry vouching for both) run a real EU-style credential lifecycle on testnet.

## Why this exists

Every credential exchange asks two independent questions:

1. Is the data **cryptographically valid**? (signature, integrity, expiry)
2. Should you actually **trust the parties**? (is the issuer accredited to issue this? is the verifier authorized to request it?)

OpenID4VCI and OpenID4VP only answer #1. A valid signature from an unknown or unaccredited party still passes. This plugin answers #2, live and on-chain, at the two moments in the flow where it matters. It is the step eIDAS 2 requires (relying parties must be registered and authorized for exactly what they request) and the base EUDI stack leaves open.

## Architecture

Three layers:

- **`@credo-ts/openid4vc`** — the protocol engine (offers, credential requests, DCQL matching, `direct_post.jwt`). The plugin drives it, it does not reimplement it.
- **`vs-agent`** — the NestJS host: DID management, HTTP, multi-role agents.
- **this plugin** — the glue plus the Verana brain: the trust client, the fail-closed consent gate, and the demo REST surface.

Three roles, toggled by config (`issuerEnabled` / `verifierEnabled` / `holderEnabled`), typically deployed as three agents:

- **Issuer** — runs OID4VCI, mints an SD-JWT VC.
- **Wallet (holder)** — holds the credential and hosts the consent gate. Verify-the-verifier happens here, before anything is disclosed.
- **Verifier** — runs OID4VP, requests the credential, and checks the issuer after cryptographic verification passes.

## End-to-end flow

**Issuance (OID4VCI, pre-authorized code)**
1. Issuer `createOffer` builds a pre-auth offer. Format is SD-JWT VC; the configured claims are selectively disclosable.
2. `buildCredentialRequestToCredentialMapper` signs the credential with an x5c chain (self-signed P-256, `alg ES256`). The signing key is also published in the issuer's DID document.
3. Wallet accepts and holds the SD-JWT VC.

**Presentation (OID4VP 1.0)**
4. Verifier `createRequest` builds a DCQL query for the `vct` and claims, signed x5c, `clientIdPrefix: x509_hash`, `responseMode: direct_post.jwt`. Two tenants exist: `trusted` (the cert's URI SAN is its real registered DID) and `rogue` (SAN is an off-registry DID). This produces a genuinely untrusted verifier with no on-chain setup.
5. **[Verana hook #1, verify the verifier]** Wallet `resolveRequest` extracts the verifier DID from the request cert's SAN and asks Verana `verdictFor('verifier', did, vtjscId)`. It stores the verdict and the disclosure in a `GateStore` behind a fresh UUID, and returns only the verdict. The disclosure never leaves this call.
6. **[the fail-closed gate]** Wallet `share(gateId)`: if the stored verdict is not exactly `TRUSTED_AUTHORIZED`, it throws `GateBlockedError` (HTTP 403) before Credo discloses anything. The gate is single-use.
7. **[Verana hook #2, verify the issuer]** Verifier `getSession` runs trust logic only once Credo reports `ResponseVerified` (crypto done). It extracts the issuer DID from the presented credential's cert SAN and asks `verdictFor('issuer', did, vtjscId)`.
8. Both verdicts plus the on-chain evidence are assembled into a `ProofOfTrustReceipt`.

## Where Verana plugs in

`src/trust/` is the whole trust brain:

- **`TrustClient`** — `resolve(did)` (Q1: is the DID a trusted Verifiable Service?), `checkAuthorization(role, did, vtjscId)` (Q2 = issuer-authorization, Q3 = verifier-authorization), and `verdictFor(role, did, vtjscId)` which composes them.
- **`computeVerdict`** (`verdict.ts`) — never fails open:
  - resolver unreachable → `RESOLVER_UNAVAILABLE` (blocks)
  - DID not found / not `TRUSTED` → `UNTRUSTED` (blocks)
  - `TRUSTED` but authorization fails/unreachable → `RESOLVER_UNAVAILABLE` (blocks)
  - `TRUSTED` + `authorized:true` → `TRUSTED_AUTHORIZED` (the only pass)
  - `TRUSTED` + `authorized:false` → `TRUSTED_NOT_AUTHORIZED` (blocks)

Important: `vtjscId` must be the **VTJSC URL** (e.g. `https://<issuer>/vt/schemas-<name>-jsc.json`), not the `vpr:` schema reference. The resolver keys authorization on the URL form.

## Key design decisions

- **The wallet trusts no certificate on its own.** `setupOpenId4Vc` configures Credo's `X509Module` to accept any presented chain (self-signed included). The cert only proves key possession; authorization is delegated entirely to the Verana verdict computed afterward.
- **The gate is server-side, fail-closed, and single-use.** Only `TRUSTED_AUTHORIZED` opens it; every other state (including "resolver down") blocks. Disclosure is held in `GateStore` and never returned until the gate opens.
- **SD-JWT VC carries no `credentialSchema`,** so the VTJSC is mapped out-of-band via the `vtjscId` config option (unlike JSON-LD `ldp_vc`, which can carry it in-band).

## Real-wallet interoperability

Validated end-to-end against the **EUDI reference wallet** (`eu-digital-identity-wallet/eudi-app-android-wallet-ui`): full OID4VCI issuance, including a real Wallet Unit Attestation the issuer accepts. Three behaviors bridge Credo to what real EU wallets require:

- **Issues `dc+sd-jwt`** (the renamed SD-JWT VC media type), with `vc+sd-jwt` kept as a fallback credential configuration. `IssuerService` signs each credential with the format of the configuration the wallet requested.
- **Advertises attestation-based client auth.** Credo hardcodes its `/.well-known/oauth-authorization-server` metadata; an issuer-only middleware (`advertiseClientAttestationMetadata`) overlays `client_attestation_pop_signing_alg_values_supported` (which EUDI wallet-core pre-flights on) plus the related fields.
- **Serves `/.well-known/jwt-vc-issuer`** with the issuer's signing JWKS, for SD-JWT VC issuer-key discovery by wallets that require it even when the credential carries an x5c chain.

Wallets enforce different policy on the same protocol (media type, attestation, issuer/reader trust); target the EUDI ARF / HAIP profile (`dc+sd-jwt`) and serve the union of discovery endpoints. The Verana trust verdict is independent of all of this — it is a server-side resolver call, identical across wallets and formats.

## Configuration

`OpenId4VcPluginOptions` (`src/types.ts`):

| Option | Purpose |
|---|---|
| `publicApiBaseUrl` | This agent's public base URL (issuer identifier, cert SAN) |
| `issuerEnabled` / `verifierEnabled` / `holderEnabled` | Role toggles |
| `resolverUrl` | Verana Trust Resolver base URL |
| `vct` | The credential type this agent issues/requests |
| `vtjscId` | The VTJSC **URL** used for issuer/verifier authorization |
| `rogueVerifierDid` | Off-registry DID for the demo's untrusted verifier tenant |

## Demo REST API (`/oid4vc-demo/*`)

Issuance: `POST /offers`, `GET /offers/:id`, `POST /wallet/accept-offer`, `GET|DELETE /wallet/credentials`.
Presentation: `POST /verifier/requests` (`{tenant: 'trusted'|'rogue'}`), `POST /wallet/resolve-request`, `POST /wallet/share`, `GET /verifier/sessions/:id`.

## Source map

- `nestjs/OpenId4VcPlugin.ts` — plugin factory, wires services + controllers per role flags
- `nestjs/{Issuer,Verifier,Wallet}Controller.ts` — the demo REST endpoints
- `services/IssuerService.ts` — OID4VCI issuance, SD-JWT mapper, x5c signing
- `services/VerifierService.ts` — OID4VP request, DCQL, trusted/rogue tenants, post-crypto issuer check
- `services/WalletService.ts` — holder API, verify-the-verifier, the fail-closed gate
- `services/GateStore.ts` — single-use gate storage
- `services/receipt.ts` — the Proof-of-Trust receipt
- `services/AgentSetup.ts` — P-256 cert with DID-in-SAN, `didFromCertificateSan`
- `sdk/setupOpenId4Vc.ts` — Credo module setup + Express mount
- `trust/` — `TrustClient`, `computeVerdict`, types

## Toward upstream (Milestone B: de-hardcoding)

This plugin currently carries a few Unfold-specific constants that must be lifted to config or derived before it is a drop-in for any ecosystem:

- `ISSUER_ID` and issuance constants (`CREDENTIAL_CONFIGURATION_ID`, `DISCLOSURE_FRAME`) in `IssuerService`
- the hardcoded registry block (`trustRegistry`, `schema`) in `receipt.ts`
- `VctController` currently ignores `options.vct`
- the real cert→DID binding: the verifier should verify the presented credential's signing key against the issuer's DID document, rather than trusting the SAN-asserted DID (a documented demo-profile limitation)
- verify whether the issuance format string and the DCQL query format string are intentionally split across SD-JWT VC draft media types, or should match

See `docs/specs/2026-07-06-vs-agent-openid4vc-upstream-design.md` in the integration repo for the full de-hardcoding design.
