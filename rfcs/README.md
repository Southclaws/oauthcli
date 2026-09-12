# OAuth 2.0 / OIDC specification texts

Verbatim specification texts for OAuth 2.0, its extensions, and OpenID Connect Core.

## Core framework

| File                                                | Covers                                                                                                                                                                                                                   |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rfc6749-oauth2-authorization-framework.txt`        | OAuth 2.0 itself: the four grant types (authorization code, implicit, password, client credentials), client registration and authentication, the authorization and token endpoints, refresh tokens, and error responses. |
| `rfc6750-bearer-token-usage.txt`                    | How to present a bearer access token to a resource server (`Authorization: Bearer`, form body, query) and the `WWW-Authenticate` challenge with `invalid_token` / `insufficient_scope` errors.                           |
| `draft-oauth-v2-1.txt`                              | OAuth 2.1 consolidation draft (`draft-ietf-oauth-v2-1-15`): folds 6749, 6750, PKCE, native apps, and the security BCP into one document; removes the implicit and password grants and mandates PKCE. Not yet an RFC.     |
| `rfc9700-oauth2-security-best-current-practice.txt` | Security BCP. Current threat model and required mitigations: exact redirect-URI matching, PKCE everywhere, sender-constrained or audience-restricted tokens, refresh-token rotation, mix-up and code-injection defences. |

## Client and app profiles

| File                                      | Covers                                                                                                                                                                                      |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rfc7636-pkce.txt`                        | PKCE: `code_verifier` / `code_challenge` (`S256`) binding an authorization code to the client instance that requested it, defeating code interception.                                      |
| `rfc8252-oauth2-for-native-apps.txt`      | Best practice for mobile and desktop clients: system browser rather than embedded webview, loopback / private-URI-scheme / app-claimed-HTTPS redirects, public clients with PKCE.           |
| `rfc8628-device-authorization-grant.txt`  | Device flow for input-constrained devices (TVs, CLIs, headless hardware): device and user codes, a verification URI, and token-endpoint polling with `authorization_pending` / `slow_down`. |
| `rfc7591-dynamic-client-registration.txt` | Programmatic client registration: the client metadata vocabulary, the registration endpoint, software statements, and issued `client_id` / `client_secret`.                                 |

## Tokens and keys

| File                                        | Covers                                                                                                                                                                                     |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rfc7519-jwt.txt`                           | JSON Web Token: claims-set encoding as a signed (JWS) or encrypted (JWE) compact token, registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`), and validation rules.         |
| `rfc7517-jwk.txt`                           | JSON Web Key and JWK Set: how public keys are represented and published (the `jwks_uri` document) for verifying token signatures, plus `kid` selection and thumbprints.                    |
| `rfc9068-jwt-profile-for-access-tokens.txt` | Interoperable JWT access tokens: the `at+jwt` type, required claims, and how a resource server validates issuer, audience, scope, and authentication context.                              |
| `rfc7523-jwt-bearer-assertion.txt`          | JWTs as authorization grants and as client credentials (`urn:ietf:params:oauth:grant-type:jwt-bearer`, `client_assertion`) — the basis of service-account and private-key-JWT client auth. |
| `rfc8693-token-exchange.txt`                | Token exchange grant: trading one token for another for delegation (`act`) and impersonation, with `subject_token`, `actor_token`, and `requested_token_type`.                             |

## Endpoints and protocol extensions

| File                                                     | Covers                                                                                                                                                                               |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `rfc7662-token-introspection.txt`                        | The introspection endpoint: a resource server asks the authorization server whether an opaque token is active and gets back its scope, client, subject, and expiry.                  |
| `rfc7009-token-revocation.txt`                           | The revocation endpoint: a client invalidates an access or refresh token, and the cascade semantics between the two.                                                                 |
| `rfc8414-authorization-server-metadata.txt`              | Authorization server discovery: the `/.well-known/oauth-authorization-server` metadata document listing endpoints, supported grants, scopes, and signing algorithms.                 |
| `rfc9126-pushed-authorization-requests.txt`              | PAR: the client POSTs the authorization request to a back channel first and sends only a `request_uri` through the browser, keeping parameters confidential and integrity-protected. |
| `rfc8707-resource-indicators.txt`                        | The `resource` parameter, letting a client name the target service so the authorization server can audience-restrict the issued token.                                               |
| `rfc9207-authorization-server-issuer-identification.txt` | The `iss` parameter on the authorization response, so a client with several configured authorization servers cannot be tricked into a mix-up attack.                                 |

## OpenID Connect

| File                          | Covers                                                                                                                                                                                                                                                                            |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `openid-connect-core-1_0.txt` | OpenID Connect Core 1.0 (errata set 2): the identity layer over OAuth 2.0 — ID Token, authentication request parameters (`nonce`, `prompt`, `max_age`, `acr`), the UserInfo endpoint, standard claims, and the code / implicit / hybrid flows. Converted from the published HTML. |

## Added for oauthcli

| File                                                 | Covers                                                                                                                  |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `openid-connect-discovery-1_0.txt`                   | OpenID Connect Discovery: the `openid-configuration` document, its required members, and issuer validation.             |
| `rfc7592-dynamic-client-registration-management.txt` | Reading, updating and deleting a dynamically registered client with `registration_client_uri` and its access token.     |
| `rfc9449-dpop.txt`                                   | DPoP: sender-constraining tokens with a proof JWT, `DPoP-Nonce`, `cnf.jkt`, and the `DPoP` authorization scheme.        |
| `rfc9728-protected-resource-metadata.txt`            | Protected resource metadata at `/.well-known/oauth-protected-resource` and the `resource_metadata` challenge parameter. |
| `rfc7518-jwa.txt`                                    | JSON Web Algorithms: the registered `alg` values, RSA key size minimum, and JWK parameters for each key type.           |
| `rfc7638-jwk-thumbprint.txt`                         | JWK Thumbprint: the canonical members hashed for each key type.                                                         |
| `rfc8725-jwt-best-current-practices.txt`             | JWT BCP: rejecting `alg: none`, algorithm confusion, and validation pitfalls.                                           |
| `rfc8996-deprecating-tls-1.0-1.1.txt`                | BCP 195: TLS 1.0 and 1.1 must not be used.                                                                              |
| `rfc9325-tls-recommendations.txt`                    | BCP 195: TLS 1.2 configuration recommendations and the TLS 1.3 recommendation.                                          |
| `draft-ietf-oauth-client-id-metadata-document.txt`   | Client ID metadata documents: an https URL as `client_id` serving the client's metadata (draft -02).                    |

## Licence

The IETF documents (RFCs and Internet-Drafts) are reproduced in full and without modification, as the IETF Trust Legal Provisions Relating to IETF Documents permit; each carries its own copyright notice and is subject to BCP 78. Internet-Drafts are work in progress and expire. The OpenID Foundation documents are reproduced under the licence in their Notices appendix, which permits reproduction and distribution for the purpose of implementing the specifications, with attribution to the OpenID Foundation as the source. The texts are embedded in the `oauthcli` binary by the `rfcs` Go package and shown by `oauthcli reference`.
