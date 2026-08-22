# CLI reference

WireLinter has two layers of CLI:

1. a user-facing shorthand that hides internal pack IDs when possible;
2. explicit commands for scripts, CI and advanced debugging.

## First-run and shorthand commands

```text
wirelint
wirelint integrations [--region <code>]
wirelint <integration> <local-webhook-url>
wirelint <integration> <provider-base-url>
wirelint <integration> <capture.json>
wirelint demo
wirelint version
```

`wirelint` without arguments starts a guided flow. It asks for the integration, lets the user choose the matching surface when necessary, and then asks only for the URL or capture needed for that path.

Common human aliases include:

```text
mercadopago              -> mercadopago-webhooks
whatsapp                  -> meta-whatsapp-webhooks
whatsapp verification     -> meta-whatsapp-webhook-verification
whatsapp api              -> meta-whatsapp-cloud-api
github api                -> github-graphql-api
```

Aliases are conveniences. The full bundled IDs remain valid and are still the stable identifiers used by automation.

When the second argument is an `http://` or `https://` URL, WireLinter uses the selected integration surface to choose live inbound inspection (`listen`) or outbound inspection (`proxy`) when that direction can be inferred safely.

When the second argument is not a URL, it is treated as a saved capture path and evaluated with `lint`.

Examples:

```bash
wirelint mercadopago http://localhost:8000/webhook
wirelint whatsapp http://localhost:8000/webhook
wirelint github-api https://api.github.com
wirelint github ./trace.json
```

## `integrations`

Shows the bundled integrations with human-readable names and their stable IDs.

```bash
wirelint integrations
wirelint integrations --region BR
```

Use this command when you know the provider name but are not sure which protocol surface is bundled.

`providers` remains available as the machine-oriented catalog that prints one stable provider ID per line.

## Explicit commands

```text
wirelint lint <provider> <trace.json>
wirelint lint --provider <id> <trace.json>
wirelint lint --pack <dir> <trace.json>
wirelint listen <provider> <local-webhook-url>
wirelint listen --provider <id> --forward-to <url>
wirelint listen --pack <dir> --forward-to <url>
wirelint proxy <provider> <base-url>
wirelint proxy --provider <id> --target <base-url>
wirelint proxy --pack <dir> --target <base-url>
wirelint validate-pack --provider <id>
wirelint validate-pack --pack <dir>
wirelint providers [--region <code>]
wirelint demo
wirelint version
```

Run `wirelint help` for the built-in explicit usage text.

## `demo`

Runs an offline, deterministic diagnosis using a bundled provider contract and capture. It demonstrates an HTTP `200` response that still fails because the GraphQL body contains errors.

```bash
wirelint demo
```

The demonstrated integration failure is intentional, so a successful demo exits with `0`. Invalid command usage or an internal execution error exits with `2`.

`demo` is a product demonstration and smoke test; it is not required before inspecting a real integration.

## `lint`

Evaluates a saved canonical Trace with either a bundled provider or an external pack.

For bundled providers, the shortest form is:

```bash
wirelint github ./trace.json
```

The explicit forms remain available and are useful in scripts and CI:

```bash
wirelint lint github ./trace.json
wirelint lint --provider github ./trace.json
wirelint lint --pack ./packs/custom ./trace.json
```

A provider-named flag is also accepted as a convenience, so `wirelint lint --stripe ./trace.json` is equivalent to `wirelint lint --provider stripe ./trace.json` when `stripe` is bundled in the binary.

Options:

| Option | Meaning |
| --- | --- |
| `--provider <id>` | bundled provider contract |
| `--pack <dir>` | external provider pack directory |
| `--trace <file>` | Trace JSON path; one positional path is also accepted |
| `--format text\|json` | report rendering, default `text` |

`--provider` and `--pack` are mutually exclusive.

## `listen`

Captures provider-to-application HTTP traffic, forwards it to an application and evaluates the resulting exchange.

User-facing shorthand:

```bash
wirelint stripe http://127.0.0.1:3000/webhooks/stripe
```

Explicit form:

```bash
wirelint listen stripe http://127.0.0.1:3000/webhooks/stripe
```

Options:

| Option | Meaning |
| --- | --- |
| `--provider <id>` | bundled provider contract |
| `--pack <dir>` | external provider pack directory |
| `--forward-to <url>` | application endpoint; required |
| `--addr <host:port>` | listener address |
| `--save-dir <dir>` | persist canonical Trace JSON files |
| `--allow-remote-forward` | permit a non-loopback forwarding target |
| `--allow-public-listen` | permit a non-loopback listen address |
| `--max-body-bytes <n>` | inbound request body limit |
| `--max-response-capture-bytes <n>` | response evidence capture limit |

See [Debugging live webhooks](../guides/live-webhooks.md) before enabling the two remote/public flags.

## `proxy`

Captures application-to-provider HTTP traffic. The application calls the local proxy; WireLinter appends the local request path to the configured provider base URL, forwards the original request, returns the provider response and evaluates the resulting exchange.

User-facing shorthand:

```bash
wirelint github-api https://api.github.com
```

Explicit form:

```bash
wirelint proxy github-graphql-api https://api.github.com
```

The default local address is `127.0.0.1:4546`. In the example above, an application request to `http://127.0.0.1:4546/graphql` is sent upstream to `https://api.github.com/graphql`.

Options:

| Option | Meaning |
| --- | --- |
| `--provider <id>` | bundled provider contract |
| `--pack <dir>` | external provider pack directory |
| `--target <base-url>` | upstream provider base URL; required |
| `--addr <host:port>` | local proxy address |
| `--save-dir <dir>` | persist canonical Trace JSON files |
| `--allow-public-listen` | permit a non-loopback local proxy address |
| `--max-body-bytes <n>` | outbound request body limit |
| `--max-response-capture-bytes <n>` | provider response evidence capture limit |

The configured target may be remote; that is the purpose of this acquisition path. The local listening socket remains loopback-only unless explicitly opted into public listening.

The proxy does not follow upstream redirects. Common credential-bearing headers and query parameters are redacted in Trace evidence, while the original request is forwarded upstream unchanged. Bodies are not generically redacted.

See [Debugging outbound APIs](../guides/outbound-apis.md).

## `providers`

Prints one bundled stable provider ID per line. This is primarily useful for scripts and CI.

```bash
wirelint providers
wirelint providers --region BR
```

For humans, prefer:

```bash
wirelint integrations
```

The region filter is an exact match against pack metadata. A contract can be globally usable while still being tagged for a regional ecosystem.

## `validate-pack`

Loads and validates a provider pack without evaluating a Trace.

```bash
wirelint validate-pack --provider github
wirelint validate-pack --pack ./packs/github
```

The output includes the pack version, Pack Protocol and counts for rules, signatures, secret matches, digest matches and schemas.

## `version`

```bash
wirelint version
```

Release builds inject the product version at build time. Source builds may report a development value.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | analysis completed without error-level failures, or a long-running acquisition command stopped cleanly |
| `1` | `lint` completed and found error-level failures |
| `2` | invalid input, pack/configuration error, acquisition error or internal execution failure |

Live `listen` and `proxy` diagnostics are reported per exchange while the process keeps serving traffic; an individual rule failure does not stop the acquisition command.

An `open` rule is not itself an execution error. See [Result semantics](results.md).
