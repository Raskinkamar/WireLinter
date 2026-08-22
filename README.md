<p align="center">
  <img src="assets/download.png" alt="WireLinter — Lint for Integrations" width="520" />
</p>

# WireLinter

WireLinter is a local-first integration linter. It watches the real HTTP exchange between your app and a provider and tells you when the integration is wrong even when the request itself appears to have worked.

It catches things such as invalid signatures, changed raw bodies, missing headers, bad payloads, slow acknowledgements and semantic errors hidden inside HTTP `200` responses.

WireLinter stays next to your application while you debug. It is not a production webhook receiver, public tunnel or general API client.

## Quick start

Install the standalone binary on Linux or macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.sh | sh
```

On Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.ps1 | iex
```

Then just run:

```bash
wirelint
```

WireLinter asks which integration you want to inspect and guides you from there. You do not need to know pack IDs, Trace JSON or the internal commands to get started.

You can also skip the prompts when you already know what you want:

```bash
# Incoming webhook
wirelint mercadopago http://localhost:8000/webhook

# WhatsApp webhook
wirelint whatsapp http://localhost:8000/webhook

# Outbound API
wirelint github-api https://api.github.com
```

Browse the bundled integrations with friendly names:

```bash
wirelint integrations
wirelint integrations --region BR
```

Want to see the report format without configuring anything?

```bash
wirelint demo
```

## What the result means

WireLinter does not collapse everything into success/failure:

```text
pass           enough evidence exists and the rule passed
fail           enough evidence proves the rule was violated
open           the rule applies, but the capture cannot prove the result
notApplicable  the rule does not apply to this exchange
```

`open` is intentional: if a secret or another piece of evidence is missing, WireLinter says it cannot prove the result instead of guessing.

## Inspect a live webhook

Point WireLinter at the webhook endpoint already running in your application:

```bash
export STRIPE_WEBHOOK_SECRET='whsec_...'
wirelint stripe http://127.0.0.1:3000/webhooks/stripe
```

WireLinter listens locally on `http://127.0.0.1:4545/`, forwards the exact request body to your application and prints a report after every delivery.

Configure the provider, tunnel or local provider CLI to send the webhook to WireLinter instead of directly to your app. For Stripe CLI, for example:

```bash
stripe listen --forward-to http://127.0.0.1:4545/
```

Trace persistence is off by default because webhook bodies can contain sensitive data. Advanced users can opt into it with `--save-dir`.

The explicit command remains available:

```bash
wirelint listen stripe http://127.0.0.1:3000/webhooks/stripe
```

See [Debugging live webhooks](docs/guides/live-webhooks.md).

## Inspect an outbound API

For an outbound integration, give WireLinter the provider base URL:

```bash
wirelint github-api https://api.github.com
```

WireLinter starts a local proxy on `http://127.0.0.1:4546/`. Point your application's provider base URL at that local address while debugging.

For GitHub GraphQL, for example, the app can call:

```text
http://127.0.0.1:4546/graphql
```

WireLinter forwards the request to GitHub, returns the provider response to your app and evaluates the captured exchange. That lets it distinguish HTTP transport success from a GraphQL `errors` result inside the response body.

The explicit form remains available:

```bash
wirelint proxy github-graphql-api https://api.github.com
```

Common credential-bearing headers and query parameters are redacted in outbound evidence before optional persistence. Request and response bodies can still contain sensitive data.

See [Debugging outbound APIs](docs/guides/outbound-apis.md).

## Analyze a saved capture

Saved captures are useful for reproducing a problem or running WireLinter in CI, but they are not required for normal first use.

The short form is:

```bash
wirelint github ./examples/traces/github-valid.json
```

The explicit form remains available for scripts and CI:

```bash
wirelint lint --provider github ./examples/traces/github-valid.json
```

## Integration contracts

An integration ID describes a concrete protocol surface, not an entire company. Different authentication modes, traffic directions or setup phases remain separate when their behavior differs materially.

For example:

- `github` describes inbound GitHub webhook delivery while `github-graphql-api` describes outbound GitHub GraphQL calls;
- `meta-whatsapp-webhook-verification`, `meta-whatsapp-webhooks` and `meta-whatsapp-cloud-api` separate callback verification, signed delivery and outbound message calls;
- `gitlab-webhooks` and `gitlab-webhooks-secret-token` are different authentication contracts;
- `vtex-order-hook-setup-ping` and `vtex-order-hook-delivery` cover different phases of the same integration;
- `docusign-connect-hmac-single-key` intentionally does not claim every DocuSign Connect key configuration.

Users normally do not need to type these full IDs. The CLI resolves human aliases when the choice is unambiguous and asks when it is not.

```bash
wirelint integrations
wirelint integrations --region BR
```

Read [Provider contracts](docs/reference/provider-contracts.md) for naming, secrets, validation and scope.

## How it works

Every acquisition path produces the same canonical Trace internally. A provider pack evaluates that evidence with JSON Schema, CEL and a small set of trusted primitives for operations that should not expose secret material to pack code.

```text
saved capture / inbound listener / outbound proxy
                       |
                       v
                     Trace
                       |
                       v
                 provider pack
                   /   |    \
              schema  CEL  trusted primitives
                             |
                             v
                           Report
```

Those are implementation concepts, not prerequisites for using the CLI. Provider-specific policy belongs in `packs/`; the Go core implements reusable mechanisms rather than vendor-specific branches.

Current Pack Protocol generations are:

- **1.0** — JSON Schema and CEL rules;
- **1.1** — declarative signature recipes;
- **1.2** — evidence-aware `requires` semantics;
- **1.3** — trusted exact secret matching;
- **1.4** — trusted SHA-256 digest matching for keyed preimage contracts.

See [Core concepts](docs/core-concepts.md) and [Architecture decisions](docs/architecture/README.md).

## Advanced CLI

The stable explicit commands remain available for automation and advanced workflows:

```text
wirelint lint
wirelint listen
wirelint proxy
wirelint providers
wirelint validate-pack
wirelint demo
wirelint version
```

Run `wirelint help` or read the [CLI reference](docs/reference/cli.md) for flags and advanced options.

## Documentation

- [Getting started](docs/getting-started.md)
- [Core concepts](docs/core-concepts.md)
- [CLI reference](docs/reference/cli.md)
- [Result semantics](docs/reference/results.md)
- [Provider contracts](docs/reference/provider-contracts.md)
- [Debugging live webhooks](docs/guides/live-webhooks.md)
- [Debugging outbound APIs](docs/guides/outbound-apis.md)
- [Writing provider packs](docs/extending/provider-packs.md)
- [Development guide](docs/development.md)
- [Security model](SECURITY.md)

The documentation index is at [`docs/README.md`](docs/README.md).

## Repository layout

```text
cmd/        executable entrypoints
internal/   engine, pack loader, live acquisition and trusted runtime
packs/      bundled provider contracts
schemas/    public JSON schemas used by the protocol
examples/   canonical traces used in examples and tests
scripts/    build and release tooling
docs/       user guides, reference material and ADRs
```

See [Development](docs/development.md) before changing the core.

## Contributing

Provider changes must be backed by primary provider documentation or an official SDK. A core change should solve a provider-neutral mechanism rather than a single vendor case.

Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
