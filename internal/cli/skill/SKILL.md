---
name: oauthcli
description: Test, validate and exercise OAuth 2.0, OAuth 2.1 and OpenID Connect servers with the oauthcli CLI. Read this before running any oauth command. Covers discovering what an issuer publishes, auditing it against the RFCs, obtaining tokens with every grant, decoding and verifying JWTs, asserting facts about tokens in tests, running the browser and device login flows, registering clients dynamically, and reading the JSON output. Use when the user asks to check an OAuth or OpenID server, get or inspect a token, debug a login, validate a JWT, or test an authorization server for conformance.
allowed-tools: Bash(oauthcli:*)
---

# oauthcli

A terminal toolkit for OAuth 2.0, OAuth 2.1 and OpenID Connect, for people and agents. Every command prints a styled result for a terminal and, with `--format json`, a documented JSON document for a program. Results go to stdout; progress and warnings go to stderr.

## The core loop

```bash
oauthcli discover https://auth.example.com      # 1. what does the issuer publish and support?
oauthcli check https://auth.example.com         # 2. is it conformant? one verdict per RFC
oauthcli token get --save                        # 3. get a token with the configured client
oauthcli token inspect                           # 4. decode and verify the saved token
oauthcli token expect --sub 1234 --aud my-api    # 5. assert facts; exit 5 when one fails
```

Point any command at a server with flags, or save the settings once as a profile:

```bash
oauthcli config init -n dev -i https://auth.example.com -c my-client --client-secret-file ./secret --non-interactive
oauthcli discover -p dev
```

Flags win over the profile. `OAUTH_ISSUER`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_SCOPE`, `OAUTH_REDIRECT_URI`, `OAUTH_TOKEN` and `OAUTH_PROFILE` are read from the environment. Keep secrets out of shell history: use `--client-secret-file`, the environment, or `-` to read stdin.

## Reading results

Exit codes carry the verdict, so a script or agent can branch without parsing:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error |
| 2 | The server or a well-known document was unreachable |
| 3 | The server answered with an OAuth error such as `invalid_client` |
| 4 | A profile, saved token, metadata document or endpoint does not exist |
| 5 | An expectation did not hold, or `check` found a non-conformance |
| 6 | A token failed signature verification or is expired |

Add `--format json` to any command for the full result. The shape of each document is declared in the tool's OpenCLI specification (`opencli.yaml`), so field names are stable. Pull single values with `jq`:

```bash
oauthcli discover -f json | jq '.capabilities[] | select(.supported) | .id'
oauthcli token inspect -f json | jq .claims.sub
oauthcli check -f json | jq '.specs[] | {id, verdict}'
```

Findings appear as `issues` with `severity` (`error`, `warning`, `info`), a stable `code`, a `message`, and the `spec` section that defines the rule.

## Discover an issuer

```bash
oauthcli discover https://accounts.google.com            # every well-known document plus capabilities
oauthcli metadata https://accounts.google.com            # the metadata document, validated
oauthcli metadata --raw -f json | jq .token_endpoint     # the raw document
oauthcli jwks https://accounts.google.com                # the signing keys, validated
oauthcli jwks --kid abc123 --pem                         # one key as PEM
oauthcli resource https://api.example.com --probe        # RFC 9728 protected resource metadata
```

`discover` tries both spellings of a path-bearing issuer (RFC 8414 inserts `/.well-known/` after the host; OpenID appends it). The capability list answers "does this server support PKCE, DPoP, introspection, device flow, DCR, PAR, token exchange...".

## Audit an issuer

```bash
oauthcli check https://auth.example.com                  # anonymous: metadata, keys, TLS, endpoint behaviour
oauthcli check -p dev                                    # with credentials: tokens, introspection, revocation, DPoP, PAR, device
oauthcli check -p dev --register --negative              # also DCR (creates and deletes a client) and a wrong-secret probe
oauthcli check -p dev --only rfc7636,oauth2.1            # a subset, by specification id
oauthcli check -p dev --show problems                    # only failing and warning checks
oauthcli check -p dev -f markdown > report.md            # a report for a pull request
```

Each specification gets a verdict: **supported, conformant**; **supported, non-conformant**; **not supported**; or **not tested** (needs credentials). `check` exits 5 when any specification is non-conformant (`--fail-on warn` to also fail on warnings). Checks that create state on the server are opt-in (`--register`). A user-supplied `--token` is validated but never revoked; the audit revokes only tokens it obtained itself.

Specification ids: `rfc8414`, `oidc-discovery`, `tls`, `rfc7517`, `rfc6749`, `rfc7636`, `oauth2.1`, `rfc9068`, `rfc6750`, `oidc-core`, `rfc7662`, `rfc7009`, `rfc8628`, `rfc9126`, `rfc9449`, `rfc8707`, `rfc7523`, `rfc8693`, `rfc7591`, `rfc9728`, `rfc9207`, `rfc8705`, `rfc9101`, `rfc9396`, `cimd`.

## Obtain a token

```bash
oauthcli token get -p dev --save                                  # client_credentials, saved for later commands
oauthcli token get -i URL -c ID --client-secret-file F -s read    # one-off, no profile
oauthcli token get -f plain | oauthcli token inspect -               # pipe the access token onward
oauthcli token get --dpop --save                                  # DPoP-bound token (RFC 9449)
oauthcli token get --resource https://api.example.com             # resource indicator (RFC 8707)
oauthcli token get -g refresh_token --refresh-token "$RT"          # refresh
oauthcli token get -g token-exchange --subject-token "$AT"         # RFC 8693
oauthcli token get -g jwt-bearer --assertion "$JWT"                # RFC 7523
oauthcli token get -g password -u alice --password "$PW"           # legacy only; OAuth 2.1 removes it
oauthcli token refresh --save                                     # refresh the saved token in place
```

Client authentication is chosen automatically from what the server advertises and the credentials given: `private_key_jwt` with `--client-key`, `client_secret_basic` with a secret, `none` for a public client. Force one with `--auth-method`.

A token saved with `--save` is used by every later command that takes a `TOKEN` argument when none is given. `oauthcli token status` lists saved tokens; `oauthcli token clear` forgets them.

## Decode, verify and assert

```bash
oauthcli token inspect                                   # the saved token
oauthcli token inspect "$TOKEN"                          # a token from an argument
oauthcli token inspect - < token.txt                     # from stdin (keeps it out of history)
oauthcli token inspect --secret "$HMAC" "$TOKEN"         # HS256 token
oauthcli token inspect --id-token "$IDT"                 # OpenID Connect ID token rules
oauthcli token introspect                                # ask the server (RFC 7662)
oauthcli token revoke --verify                           # revoke and confirm inactive (RFC 7009)
oauthcli userinfo                                        # call the UserInfo endpoint
```

`token inspect` verifies the signature against the issuer's key set (from the `iss` claim or the configured issuer), reports expiry in human terms, and flags problems such as `alg: none`, a missing `exp`, or an `at+jwt` header missing required claims.

For tests, `token expect` exits 5 when any expectation fails and 0 when all hold:

```bash
oauthcli token expect --sub 1234 --aud https://api.example.com --scope-includes read
oauthcli token expect --claim 'email~@example\.com$' --claim role=admin --claim 'groups+=staff'
oauthcli token expect --typ at+jwt --alg RS256 --max-ttl 1h --has jti --missing password
oauthcli token expect --active                           # also require introspection to say active
oauthcli token expect -q ... && echo ok                  # quiet: the exit code is the result
```

`--claim name=value` compares the string form; `name~regex` matches a regular expression; `name+=member` requires membership in an array claim. Signature verification and expiry are checked by default; `--no-verify` and `--allow-expired` turn them off.

## Log in interactively

```bash
oauthcli flow code -p dev                                # authorization code + PKCE, opens the browser, saves the token
oauthcli flow code -s openid,email --par                 # push the request first (RFC 9126)
oauthcli flow code --no-browser                          # print the URL; a person opens it
oauthcli flow code --manual -r https://app/callback      # no listener; paste the redirect URL back
oauthcli flow device --qr                                # device flow (RFC 8628) with a QR code
```

`flow code` listens on a loopback redirect URI (default `http://127.0.0.1:<free port>/callback`; set `--port` or `-r` to match what is registered), generates `state`, PKCE and (with `openid`) `nonce`, validates the callback (state, RFC 9207 `iss`), exchanges the code, and validates the ID token (issuer, audience, nonce, `at_hash`). The authorization URL is always printed to stderr, so an agent can hand it to a person and keep waiting.

When an agent runs a login for a person: run `oauthcli flow code --no-browser`, give the person the URL, and wait; the command returns when the browser comes back. On a headless machine use `--manual` and paste the final redirect URL when prompted.

## Register clients

```bash
oauthcli client register -n "my client" -r http://127.0.0.1:8085/callback --save   # RFC 7591, saved into the profile
oauthcli client register --from client.json --initial-token "$TOKEN"
oauthcli client get                                      # RFC 7592 read, using the saved handle
oauthcli client update -n "renamed"
oauthcli client delete --yes
oauthcli cimd new https://app.example.com/oauth/client.json -r https://app.example.com/callback > client.json
oauthcli cimd check https://app.example.com/oauth/client.json
```

A client ID metadata document (CIMD) lets a client identify itself with an https URL that serves its metadata; `cimd new` writes one, `cimd check` validates one and reports whether the configured issuer advertises support.

## Profiles

```bash
oauthcli config init                         # interactive form; offers what the issuer advertises
oauthcli config list                         # every profile, with a marker on the default
oauthcli config show                         # the settings the next command would use (secrets masked)
oauthcli config show --reveal -f json        # the same, for a script
oauthcli config set client.authMethod private_key_jwt -n dev
oauthcli config use dev
oauthcli config path                         # where the file lives
oauthcli config remove old --yes
```

Settable keys: `issuer`, `client.id`, `client.secret`, `client.secretFile`, `client.key`, `client.authMethod`, `scopes`, `redirectUri`, `audience`, `resources`, `insecure`, `allowHttp`, `description`.

## Read the specification behind a finding

Every finding names a specification and section. The texts are embedded in the binary, so read the sentence behind a finding without the network:

```bash
oauthcli reference                                # list the embedded specifications
oauthcli reference rfc6749 --section 5.2           # token endpoint error responses
oauthcli reference oidc-core --section 3.1.3.7     # ID token validation
oauthcli reference oauth2.1 --section 4.1.2.1      # PKCE enforcement at the authorization endpoint
oauthcli reference dpop --section 4.2              # aliases work: pkce, dcr, par, dpop, prm, jwt, jwk
oauthcli reference 9728 -f json | jq -r '.[0].text' | head -50
```

Ids: `rfc6749`, `rfc6750`, `oauth2.1`, `rfc9700`, `rfc7636`, `rfc8252`, `rfc8414`, `rfc7591`, `rfc7592`, `rfc7662`, `rfc7009`, `rfc8628`, `rfc9126`, `rfc9449`, `rfc8707`, `rfc7523`, `rfc8693`, `rfc9068`, `rfc9207`, `rfc9728`, `cimd`, `rfc7519`, `rfc7517`, `rfc7518`, `rfc7638`, `rfc8725`, `rfc8996`, `rfc9325`, `oidc-core`, `oidc-discovery`. A bare number such as `6749` also works.

## Building requests by hand

```bash
oauthcli pkce                                # a fresh code_verifier and S256 code_challenge
oauthcli pkce -f plain | cut -f2             # just the challenge
oauthcli pkce --verifier "$VERIFIER"          # the challenge of an existing verifier
```

## Debugging

- `--trace` prints every HTTP request and response on stderr with secrets redacted.
- `-v` adds progress notes; `-vv` implies `--trace`.
- `--insecure` accepts a bad TLS certificate; `--allow-http` permits plain http beyond loopback. Both are recorded in the audit.
- `-H 'Name: value'` adds a header to every request (a tenant header, a proxy token).
- `--timeout 30s` for a slow server.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| exit 4, `no metadata document found` | The URL is not an issuer. Try the host without a path, or run `oauthcli discover` to see which locations answer. |
| exit 3, `invalid_client` | Wrong client id or secret, or the wrong authentication method. Check `oauthcli metadata` for `token_endpoint_auth_methods_supported` and force one with `--auth-method`. |
| exit 6 on `token inspect` | Signature or expiry failed. Read the `Signature` line: no matching `kid` means the key set rotated or the issuer is different. |
| `state mismatch` in `flow code` | The browser came back with a response from another request. Run the flow again without reusing tabs. |
| `redirect URI ... is not a loopback address` | The registered redirect URI is not on 127.0.0.1 or localhost. Use `--manual` and paste the redirect URL back, or register a loopback URI. |
| `refusing plain http` | OAuth requires TLS. Loopback http is allowed; anything else needs `--allow-http`. |

## When to use what

- Learn about a server: `discover`, then `metadata`, `jwks`, `resource`.
- Judge a server: `check`.
- Get a credential without a person: `token get`.
- Get a credential with a person: `flow code` (browser) or `flow device` (no browser).
- Understand a credential: `token inspect`, `token introspect`, `userinfo`.
- Test a credential in CI or an agent plan: `token expect`.
- Set up a client on the server: `client register`, `cimd new`.
