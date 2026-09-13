# oauthcli

A terminal toolkit for OAuth 2.0, OAuth 2.1 and OpenID Connect, built for people and for agents. It discovers what an authorization server publishes, validates it against the RFCs, obtains and decodes tokens with every grant, runs the browser and device flows, registers clients dynamically, and audits a whole installation with one command.

```sh
oauthcli discover https://accounts.google.com     # what does this issuer publish and support?
oauthcli check https://accounts.google.com        # is it conformant? one verdict per RFC
oauthcli token get -p dev --save                  # get a token with the configured client
oauthcli token inspect                            # decode and verify it
oauthcli token expect --sub 1234 --aud my-api     # assert facts about it; exit 5 on failure
```

Every command has `--format json` with a documented schema, so an agent uses the same tool a person does. The specification that generates the command tree, `opencli.yaml`, is also the behavioural contract the implementation is tested against.

## Install

```sh
go install github.com/Southclaws/oauthcli@latest
```

The binary is called `oauthcli`.

## For agents

```sh
oauthcli skill                              # usage guide with workflows and copy-paste recipes
oauthcli skill --full                       # plus a reference of every command and flag
oauthcli skill --out .claude/skills/oauth   # install it as a project skill
```

The bare command prints a cookbook, every subcommand explains itself in `--help` with examples, exit codes carry the verdict, and stdout carries only results so output pipes cleanly.

| Exit code | Meaning                                                              |
| --------- | -------------------------------------------------------------------- |
| 0         | Success                                                              |
| 1         | Runtime error                                                        |
| 2         | The server or a well-known document was unreachable                  |
| 3         | The server answered with an OAuth error such as `invalid_client`     |
| 4         | A profile, saved token, metadata document or endpoint does not exist |
| 5         | An expectation did not hold, or `check` found a non-conformance      |
| 6         | A token failed signature verification or is expired                  |

## Configuration

Settings come from flags, the environment, or a profile in a configuration file. Flags win.

```sh
oauthcli config init                                   # interactive: asks the issuer what it offers
oauthcli config init -n dev -i https://auth.example.com -c app --client-secret-file ./secret --non-interactive
oauthcli config list
oauthcli config path
```

| Platform | Path                                                                   |
| -------- | ---------------------------------------------------------------------- |
| Windows  | `%AppData%/oauth/config.yaml`                                          |
| macOS    | `~/Library/Application Support/oauth/config.yaml`                      |
| Linux    | `$XDG_CONFIG_HOME/oauth/config.yaml`, or `~/.config/oauth/config.yaml` |

`--config` or `OAUTH_CONFIG` points at any other file. A profile looks like this; [`examples/config.yaml`](./examples/config.yaml) has a worked set:

```yaml
default: dev
profiles:
  dev:
    issuer: https://auth.example.com
    client:
      id: my-client
      secretFile: ~/.config/oauth/dev.secret # or secret:, or OAUTH_CLIENT_SECRET
      authMethod: auto # client_secret_basic, private_key_jwt, none, ...
    scopes: [openid, profile]
    redirectUri: http://127.0.0.1:8085/callback
```

Environment: `OAUTH_ISSUER`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET`, `OAUTH_CLIENT_KEY`, `OAUTH_SCOPE`, `OAUTH_REDIRECT_URI`, `OAUTH_AUDIENCE`, `OAUTH_TOKEN`, `OAUTH_PROFILE`, `OAUTH_CONFIG`, `OAUTH_TIMEOUT`, `OAUTH_THEME`, `NO_COLOR`.

Tokens saved with `--save` live in `tokens.json` next to the configuration file, mode 0600, and are used by later commands that take a `TOKEN` argument when none is given.

## Commands

| Area      | Commands                                                                                                                                     |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Discovery | `discover`, `metadata`, `jwks`, `resource`                                                                                                   |
| Audit     | `check`                                                                                                                                      |
| Tokens    | `token get`, `token refresh`, `token inspect`, `token introspect`, `token revoke`, `token expect`, `token status`, `token clear`, `userinfo` |
| Flows     | `flow code`, `flow device`                                                                                                                   |
| Clients   | `client register`, `client get`, `client update`, `client delete`, `cimd check`, `cimd new`                                                  |
| Utilities | `reference`, `pkce`, `skill`, `config ...`                                                                                                   |

### Discovery

```sh
oauthcli discover https://auth.example.com          # every well-known document, capabilities, keys
oauthcli metadata https://auth.example.com          # RFC 8414 / OpenID discovery document, validated
oauthcli metadata --raw -f json | jq .token_endpoint
oauthcli jwks https://auth.example.com --kid abc --pem
oauthcli resource https://api.example.com --probe   # RFC 9728 metadata and the WWW-Authenticate challenge
```

`discover` tries both spellings of a path-bearing issuer: RFC 8414 inserts `/.well-known/` after the host, OpenID Connect appends it.

### Audit

```sh
oauthcli check https://auth.example.com             # anonymous
oauthcli check -p dev                               # with credentials: tokens, introspection, revocation, DPoP, PAR, device
oauthcli check -p dev --register --negative         # also DCR (creates and deletes a client) and a wrong-secret probe
oauthcli check -p dev --only rfc7636,oauth2.1 -f json
oauthcli check -p dev -f markdown > report.md
```

Each specification is reported as **supported, conformant**, **supported, partially tested**, **supported, non-conformant**, **not supported**, or **not tested**. A partially tested verdict means at least one check produced evidence while another applicable check could not be exercised:

```
◆ Proof Key for Code Exchange (RFC 7636)   SUPPORTED · CONFORMANT
    ● code_challenge_methods_supported is advertised  RFC 8414 §2
    ● S256 is supported  §4.2
    ◐ plain is not offered  §7.2
        plain is advertised; a client may downgrade to it
    ● authorization request without PKCE is rejected  OAuth 2.1 §4.1.1
```

Specifications covered: RFC 8414, OpenID Connect Discovery, transport security (RFC 9700), RFC 7517, RFC 6749, RFC 7636, OAuth 2.1, RFC 9068, RFC 6750, OpenID Connect Core, RFC 7662, RFC 7009, RFC 8628, RFC 9126, RFC 9449, RFC 8707, RFC 7523, RFC 8693, RFC 7591 and 7592, RFC 9728, RFC 9207, RFC 8705, RFC 9101, RFC 9396, and client ID metadata documents.

Anonymous checks cover metadata, key sets, TLS, error handling at the token and authorization endpoints, and whether the authorization endpoint rejects a request without PKCE. Credentials unlock the token endpoint: a client credentials token is obtained, decoded, verified against the key set, introspected and revoked; DPoP binding, resource indicators, PAR and the device flow are tried where advertised. Checks that create state are opt-in. A `--token` you supply is validated but never revoked.

### Tokens

```sh
oauthcli token get -p dev --save                              # client_credentials
oauthcli token get -i URL -c ID --client-secret-file F -s read
oauthcli token get --dpop --save                              # DPoP-bound (RFC 9449)
oauthcli token get -g token-exchange --subject-token "$AT"    # RFC 8693
oauthcli token get -g jwt-bearer --assertion "$JWT"           # RFC 7523
oauthcli token refresh --save
oauthcli token inspect - < token.txt                          # decode, verify signature, check timing
oauthcli token introspect                                     # RFC 7662
oauthcli token revoke --verify                                # RFC 7009, then confirm inactive
oauthcli userinfo
```

Client authentication is picked from what the server advertises and the credentials given: `private_key_jwt` with `--client-key`, `client_secret_basic` with a secret, `none` for a public client. `--auth-method` forces one.

### Expectations

```sh
oauthcli token expect --sub 1234 --aud https://api.example.com --scope-includes read
oauthcli token expect --claim 'email~@example\.com$' --claim role=admin --claim 'groups+=staff'
oauthcli token expect --typ at+jwt --alg RS256 --max-ttl 1h --has jti --active
```

Exit 0 when every expectation holds, 5 when one does not. `name=value` compares the string form, `name~regex` matches, `name+=member` requires membership in an array claim.

### Flows

```sh
oauthcli flow code -p dev                    # authorization code + PKCE; opens the browser, saves the token
oauthcli flow code -s openid,email --par     # push the request first (RFC 9126)
oauthcli flow code --no-browser              # print the URL for a person to open
oauthcli flow code --manual -r https://app/callback   # no listener; paste the redirect URL back
oauthcli flow device --qr                    # device flow (RFC 8628) with a QR code
```

`flow code` listens on a loopback redirect URI, generates `state`, PKCE and (with `openid`) `nonce`, validates the callback including the RFC 9207 `iss` parameter, exchanges the code, and validates the ID token: issuer, audience, nonce, `at_hash`.

### Clients

```sh
oauthcli client register -n "my client" -r http://127.0.0.1:8085/callback --save   # RFC 7591
oauthcli client get | update | delete                                               # RFC 7592
oauthcli cimd new https://app.example.com/oauth/client.json -r https://app.example.com/callback
oauthcli cimd check https://app.example.com/oauth/client.json
```

### Piping

```sh
oauthcli token get -f plain | oauthcli token inspect -
oauthcli discover -f json | jq '.capabilities[] | select(.supported) | .id'
oauthcli check -f json | jq '.specs[] | {id, verdict}'
oauthcli jwks -f plain | cut -f1
```

`--trace` logs every HTTP exchange on stderr with secrets redacted.

## Completions

Shell completion comes from [carapace](https://carapace.sh):

```sh
oauthcli _carapace zsh >> ~/.zshrc        # or bash, fish, nushell, elvish, xonsh, powershell
```

Profiles, issuers, client ids, specification ids and scopes (fetched from the active issuer's `scopes_supported`) are completed from real values.

## Specifications

The [`rfcs/`](./rfcs) folder holds the verbatim text of every specification the checks cite: RFC 6749, 6750, 7009, 7517, 7518, 7519, 7523, 7591, 7592, 7636, 7638, 7662, 8252, 8414, 8628, 8693, 8707, 8725, 8996, 9068, 9126, 9207, 9325, 9449, 9700, 9728, the OAuth 2.1 and client ID metadata document drafts, and OpenID Connect Core and Discovery. Each check names the section it enforces, and the texts are embedded in the binary, so a finding can be read next to the sentence that defines it:

```sh
oauthcli reference                              # list the embedded specifications
oauthcli reference rfc6749 --section 5.2         # one section, page headers removed
oauthcli reference oidc-core --section 3.1.3.7 | less
```

The IETF texts are reproduced unmodified under the IETF Trust Legal Provisions; the OpenID Foundation texts under the licence in their Notices appendix, for the purpose of implementing the specifications. See [`rfcs/README.md`](./rfcs/README.md).

## Development

The command tree is generated from `opencli.yaml` by [OpenCLI](https://github.com/opencli-dev/opencli):

```sh
opencli validate opencli.yaml
go generate ./internal/cli      # regenerates internal/cligen
go test ./...
```

Handlers in `internal/cli` implement behaviour only; flags, arguments, help text and output schemas come from the specification. Tests check the implementation against it: every leaf command is covered by the agent guide, every description renders correctly, and an in-process authorization server exercises the whole audit in both a conformant and a deliberately broken configuration.
