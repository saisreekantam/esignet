# Native SSO for mobile apps (eSignet Go)

OpenID Connect Native SSO for Mobile Apps 1.0 lets a user sign in once in one app of a vendor and be signed in to the vendor's other apps on the same device. They don't have to authenticate or consent again.

The implementation spans two repositories, as the problem statement requires:

| Repository | Branch | What changed |
|---|---|---|
| `thunder-id/thunderid` (fork of `v1.0.1`) | `feature/native-sso` | The protocol: the `device_sso` scope, the `DeviceSecretProvider` and `NativeSSOConsentProvider` interfaces, `device_secret` in the token response, `ds_hash`/`sid` in the ID token, and the device-secret token exchange |
| `mosip/esignet` | `feature/native-sso` | The policy: the device-secret format, keys and SSO sessions, the vendor allow-list, consent reuse and its audit trail, configuration, client registration, and the SSO logout endpoint |

## Flows

### First app ("Super App"): login with PAR, DPoP and device secret issuance

```mermaid
sequenceDiagram
    participant S as Super App
    participant T as ThunderID engine
    participant D as DeviceSecretProvider (eSignet)
    participant K as eSignet keymanager
    S->>S: generate key A in Keystore/StrongBox
    S->>T: POST /oauth2/par (scope=openid profile device_sso, dpop_jkt=jkt(A), private_key_jwt)
    S->>T: authorize, OTP login, consent (eSignet UI)
    S->>T: POST /oauth2/token (code, PKCE, DPoP proof by A)
    T->>T: device_sso granted? client allowed? openid? DPoP present? ID token unencrypted?
    T->>D: GenerateDeviceSecret(sub, auth_id, client_id, scopes, acr, claims, cnf.jkt, aci)
    D->>K: sign (ES256), then encrypt (RSA-OAEP JWE, NATIVE_SSO key)
    D->>D: open SSO session (sid)
    T->>T: ds_hash = b64url(left half of SHA-256(device_secret)); sid = auth_id
    T-->>S: access_token (DPoP-bound to A), id_token (ds_hash, sid), device_secret
```

### Second app ("Child App"): silent SSO through token exchange

```mermaid
sequenceDiagram
    participant C as Child App
    participant S as Super App (SSO bound service)
    participant T as ThunderID engine
    participant D as DeviceSecretProvider
    participant P as NativeSSOConsentProvider
    C->>S: bindService (signature permission: same signing certificate)
    S-->>C: id_token, device_secret, DPoP proof signed by A (key A never leaves the Super App)
    C->>T: POST /oauth2/token grant_type=token-exchange, subject_token=id_token, actor_token=device_secret, actor_token_type=urn:openid:params:token-type:device-secret, DPoP
    T->>T: verify ID token signature and issuer (exp not enforced, see below)
    T->>D: ValidateDeviceSecret(child, device_secret): decrypt, verify, exp, session alive, same rp_id, allow-list
    T->>T: DPoP jkt == device_secret cnf.jkt; ds_hash matches; sid, sub and aud match
    T->>T: original client still allowed device_sso; scopes are a subset (strict); no device_sso
    T->>P: ResolveNativeSSOConsent (no side effects)
    T->>D: MarkDeviceSecretUsed (atomic, once per app)
    T->>T: issue access token: sub = user, client_id = child, cnf.jkt = A, act.sub = Super App
    T->>P: RecordNativeSSOConsent (consent_history, reused_from_client_id)
    T-->>C: access_token (DPoP), issued_token_type=access_token
    C->>S: DPoP proof for GET /oauth2/userinfo (ath)
    C->>T: GET /oauth2/userinfo
```

## Problem statement tasks and where they are implemented

| # | Task | Implementation |
|---|---|---|
| 1 | `device_sso` scope on the authorize request | `granthandlers.splitDeviceSSOScope`; classified as an OIDC protocol scope in `utils.SeparateOIDCAndNonOIDCScopes`, so it is never downscoped to a resource server |
| 2 | Token endpoint checks that `allowed_authorization_scopes` includes `device_sso` | `granthandlers.validateDeviceSSORequest` (`oauthApp.Scopes` is built from `allowed_authorization_scopes` by eSignet's actor provider) |
| 3 | Device Secret Provider interface, exposed to the ThunderID engine | `providers.DeviceSecretProvider`, `thunderidengine.WithDeviceSecretProvider` |
| 4 | Generate (signed JWT with `cnf.jkt`, `auth_id`, `exp`, `client_id`, `scope`, `acr`, `claims`, `iss`) and Validate | `engine/device_secret_provider.go` (eSignet) |
| 5 | Invoke generation from the token endpoint | `granthandlers.issueDeviceSecret`, called by the authorization code grant |
| 6 | Return `access_token`, `id_token` and `device_secret` (signed-then-encrypted) | `model.TokenResponse.DeviceSecret`; the ID token carries `ds_hash` and `sid` |
| 7 | Second app retrieves the ID token, device secret and DPoP proof through an app-to-app channel | Reference model in `native-sso-lab/device.go` (signature-protected bound service; the key never leaves the Super App) |
| 8 | Token exchange with the first app's DPoP key, without `device_sso` | `native-sso-lab/client.go` (`tokenExchange`) |
| 9 | Token exchange grant: `actor_token_type` device-secret, Validate Device Secret, `ds_hash`, `sid`, `device_sso` allowed, `cnf.jkt` matches DPoP | `granthandlers.handleNativeSSOGrant`, `verifyNativeSSOIDToken` |
| 10 | Second app's scope is a subset; reject `device_sso` on token exchange | `granthandlers.nativeSSOScopes`, `validateNativeSSOExchangeRequest` |

## Security decisions

- **The device secret is opaque and sender-constrained.** It is a JWS signed with eSignet's EC P-256 key, encrypted as an RSA-OAEP JWE to a dedicated Component Encryption Key (`NATIVE_SSO`, created lazily by the keymanager). Clients can't read or forge it. It is bound to key A through `cnf.jkt`, so a stolen device secret is useless without the device key.
- **DPoP is mandatory on both legs.** `device_sso` is refused without a DPoP proof to bind the secret to. The exchange is refused unless the proof's key thumbprint equals the secret's `cnf.jkt`, compared in constant time.
- **The ID token and device secret are bound together.** `ds_hash` uses the `at_hash` construction from Native SSO 1.0: base64url of the left half of the SHA-256 hash, matching the RS256/PS256 ID token signature. `sid`, `sub` and `aud` must also match the device secret.
- **An expired ID token is accepted.** The Native SSO session lasts as long as the device secret (24 hours by default). ID tokens live 120 seconds in eSignet, so an expired ID token is still accepted as long as its signature, issuer and binding are valid. The device secret's expiry and the server-side SSO session decide whether SSO is still allowed.
- **Vendor boundary.** A device secret can be redeemed by the client it was minted for, or by a client that is both registered under the same `rp_id` and listed in the original client's `additional_config.native_sso_allowed_client_ids`. The same-`rp_id` rule also keeps the partner-specific user token (`sub`) consistent across the vendor's apps.
- **Strict scopes.** Unlike plain RFC 8693, where unknown scopes are silently dropped, a Native SSO request asking for scopes beyond the original grant, or beyond what the child app is registered for, fails with `invalid_scope`.
- **Replay protection.** Under `redemption_policy: once_per_client` (the default, following the "mark device_secret as used" step), each app can redeem a device secret once. The redemption is claimed atomically (`PutIfNotExists`), so concurrent replays lose the race. `reusable` is available for deployments that prefer a long-lived SSO session.
- **Consent reuse.** Consent is checked without side effects before the redemption is claimed, and recorded only after the token is issued. Rejected or replayed exchanges leave no audit rows. A standard scope is covered when the user accepted at least one of its claims that the child is registered for; a permission scope must have been permitted. Anything else returns `interaction_required`, and the child app falls back to its own interactive login and consent.
- **Audit trail.** Every silent sign-in appends a `consent_history` row for the child app, with the new nullable column `reused_from_client_id` naming the app whose consent was reused. `consent_detail` is left untouched because the user made no new decision. The migration is `db_upgrade_script/mosip_esignet/sql/2.0.0_to_2.1.0_upgrade.sql`.
- **Each app gets only its own claims.** The first version passed this check but leaked data. The Child App's userinfo returned the identity system's KYC record exactly as it was issued to the Super App: `aud` was the Super App and it included `email`, although the child had only asked for `openid profile`. The exchange now gives the child its own attribute set, holding only the claims the consent provider releases (claims the child is registered for ∩ claims the user accepted ∩ claims the requested scopes release). eSignet then signs a userinfo response addressed to the child. An identity record that is encrypted to the Super App can't be narrowed, so that case returns `interaction_required`. Scenario H3 asserts the audience and the absence of email.
- **Tokens end with their session.** Child access tokens carry the token family `native-sso:<sid>`. A revocation-enforcement hook asks the device secret provider (`IsSessionActive`) whether that session is still open whenever a token is validated (userinfo, introspection). Logout therefore cuts off tokens that were already issued, not just future exchanges (scenario L2: 200, then 401). The hook defers to ThunderID's regular deny-list enforcement when that is configured.
- **Global logout (beyond the problem statement).** The diagram marks "sid still active" as out of scope. eSignet tracks each SSO session server-side, and `POST /native-sso/logout` ends it for every app of the family at once.
- **ID tokens must be signed but not encrypted.** A JWE ID token is encrypted to the Super App's key and could not be presented by a sibling app, so `device_sso` is refused for clients with `id_token_response_type: JWE`.

## Configuration

`esignet-service/data/deployment.yaml`:

```yaml
oauth:
  allowed_grant_types: ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]

native_sso:
  enabled: true                       # MOSIP_ESIGNET_NATIVE_SSO_ENABLED
  device_secret_validity_secs: 86400  # MOSIP_ESIGNET_NATIVE_SSO_DEVICE_SECRET_VALIDITY_SECS
  encryption_reference_id: NATIVE_SSO # MOSIP_ESIGNET_NATIVE_SSO_ENCRYPTION_REF_ID
  redemption_policy: once_per_client  # once_per_client | reusable
```

Client registration (`POST /client-mgmt/client`). The Super App:

```json
{
  "relyingPartyId": "acme-health",
  "grantTypes": ["authorization_code"],
  "additionalConfig": {
    "require_pushed_authorization_requests": true,
    "dpop_bound_access_tokens": true,
    "require_pkce": true,
    "allowed_authorization_scopes": ["device_sso"],
    "native_sso_allowed_client_ids": ["acme-pharmacy", "acme-labs"]
  }
}
```

Each child app is registered under the same `relyingPartyId` with `"grantTypes": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"]`.

## API changes

### Token endpoint, authorization code grant with `device_sso`

```http
HTTP/1.1 200 OK
{
  "access_token": "eyJ...",          // DPoP-bound (cnf.jkt = key A); device_sso is not in its scope
  "token_type": "DPoP",
  "expires_in": 120,
  "scope": "openid profile email",
  "id_token": "eyJ...",              // carries sid and ds_hash
  "device_secret": "eyJ...5 parts"   // compact JWE, opaque to the client
}
```

### Token endpoint, Native SSO token exchange

```http
POST /oauth2/token
DPoP: <proof signed with key A>
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=acme-pharmacy
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<private_key_jwt, aud = issuer>
&subject_token=<Super App id_token>
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
&actor_token=<device_secret>
&actor_token_type=urn:openid:params:token-type:device-secret
&scope=openid profile
```

```http
HTTP/1.1 200 OK
{ "access_token": "eyJ...", "token_type": "DPoP", "expires_in": 120, "scope": "openid profile",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token" }
```

| Error | When |
|---|---|
| `invalid_dpop_proof` | No DPoP proof (on either leg) |
| `invalid_grant` | Invalid, tampered, expired, foreign or replayed device secret; DPoP key ≠ `cnf.jkt`; `ds_hash`/`sid`/`sub`/`aud` mismatch; original client lost `device_sso`; app outside the vendor allow-list; SSO session ended |
| `invalid_scope` | `device_sso` on token exchange; scope beyond the original grant or the child's registration; `device_sso` for a client not registered for it; no `openid` |
| `interaction_required` | The original consent doesn't cover the request (`error_description` lists the scopes) |
| `invalid_request` | The device-secret type used as `subject_token_type`, the subject not an ID token, or a non-access-token `requested_token_type` |

### `POST /native-sso/logout`

`device_secret=<device secret>` (form). It ends the SSO session, so no app can redeem the device secret again.

```json
{ "status": "logged_out", "signed_out_clients": ["acme-super-app", "acme-pharmacy"] }
```

## Tests

| Layer | What | Result |
|---|---|---|
| ThunderID unit tests | `granthandlers/native_sso_test.go`: issuance, every rejection path of the exchange, request shape, scope rules, per-client attributes, session enforcement | 57 cases pass |
| eSignet unit tests | `device_secret_provider_test.go`, `native_sso_consent_provider_test.go`: round trip, forgery, expiry, vendor allow-list, redemption policy, session end, consent rules, audit | 43 cases pass |
| Fuzzing | `FuzzNativeSSOScopes` (ThunderID), `FuzzValidateDeviceSecret` (eSignet) | about 3.2 million inputs, no failures |
| Mutation testing | `native-sso-lab/mutation/mutate.py` disables each of 16 security checks in turn | 16/16 caught by a test |
| End to end | `native-sso-lab`: 20 scenarios (3 happy-path, 11 attack, 2 consent, 2 race/replay, 2 logout) against a running eSignet | 20/20 pass |
| Postman | Native SSO folder, run by `native-sso-lab/postman/run-native-sso.sh` | 18/18 steps pass |
| Android | Super App and Pharmacy apps on an Android 15 emulator, with the real eSignet login UI in a Custom Tab | silent SSO, consent fallback, logout cut-off and rogue-app refusal all verified |
