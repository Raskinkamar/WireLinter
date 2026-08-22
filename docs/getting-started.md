# Getting started

This guide takes you from installation to inspecting a real integration. You do not need to understand provider packs or Trace JSON before using WireLinter.

## 1. Install

Linux and macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/Raskinkamar/WireLinter/main/scripts/install.ps1 | iex
```

Check the installed version:

```bash
wirelint version
```

For release archives and checksum verification, see [Installation](../INSTALL.md).

## 2. Start with `wirelint`

Run:

```bash
wirelint
```

WireLinter asks which integration you want to inspect and then asks only for the information needed for that path.

For an incoming webhook, that is usually just your existing local webhook URL. For an outbound API, it is the provider base URL.

If you already know what you want, skip the prompts:

```bash
wirelint mercadopago http://localhost:8000/webhook
wirelint whatsapp http://localhost:8000/webhook
wirelint github-api https://api.github.com
```

Browse integrations with:

```bash
wirelint integrations
wirelint integrations --region BR
```

The older explicit commands are still available for scripts, CI and advanced use.

## 3. Inspect a real webhook

Suppose your application receives Stripe webhooks at:

```text
http://127.0.0.1:3000/webhooks/stripe
```

If the integration uses a signing secret, expose it to WireLinter:

```bash
export STRIPE_WEBHOOK_SECRET='whsec_...'
```

Start the inspection:

```bash
wirelint stripe http://127.0.0.1:3000/webhooks/stripe
```

By default WireLinter listens on `127.0.0.1:4545`. Point the provider, tunnel or provider CLI at WireLinter instead of directly at your application.

With Stripe CLI:

```bash
stripe listen --forward-to http://127.0.0.1:4545/
```

The request path is:

```text
provider / tunnel
      |
      v
WireLinter :4545
      |
      v
local application
```

WireLinter preserves the exact request body, forwards it to your app, captures the response and evaluates the exchange after the response has been relayed.

It prints the diagnosis immediately. You do not need to create a capture file first.

Trace persistence is off by default because webhook bodies can contain sensitive data. Advanced users can add `--save-dir ./traces` when they deliberately want to keep captured evidence.

See [Debugging live webhooks](guides/live-webhooks.md) for listener options and safety boundaries.

## 4. Inspect an outbound API

Outbound integrations use the same short form. For GitHub GraphQL:

```bash
wirelint github-api https://api.github.com
```

WireLinter starts a local proxy on `127.0.0.1:4546`. Point your application's provider base URL at the local proxy while debugging.

For GitHub GraphQL, your app can call:

```text
http://127.0.0.1:4546/graphql
```

WireLinter forwards the request, returns GitHub's response to your app and evaluates both sides of the exchange.

See [Debugging outbound APIs](guides/outbound-apis.md).

## 5. Read the result

WireLinter distinguishes a failed rule from a rule it cannot prove.

- `pass` means the captured evidence was sufficient and satisfied the rule.
- `fail` means the evidence was sufficient and violated the rule.
- `open` means the rule applies, but the capture is missing evidence required for a safe decision.
- `notApplicable` means the rule does not apply to that exchange.

A missing signing secret is a common example of `open`: WireLinter does not guess whether the signature is valid when it has no key material.

The CLI exits with `0` when analysis completes without error-level failures, `1` when analysis completes with error-level failures, and `2` when the input or execution itself is invalid.

See [Result semantics](reference/results.md) for the exact model.

## 6. Saved captures are optional

Saved captures are useful for reproducing a problem or running WireLinter in CI, but they are not part of the required first-use flow.

The repository contains deterministic examples under `examples/traces/`. For example:

```bash
export GITHUB_WEBHOOK_SECRET="It's a Secret to Everybody"
wirelint github ./examples/traces/github-valid.json
```

Use JSON output when another tool will consume the report:

```bash
wirelint lint \
  --provider github \
  --format json \
  ./examples/traces/github-valid.json
```

## 7. Advanced contract work

If you are developing or validating provider contracts, the explicit commands remain available:

```bash
wirelint providers --region BR
wirelint validate-pack --provider github
wirelint validate-pack --pack ./packs/github
```

Those concepts are intentionally kept out of the normal first-run path.

## Where to go next

For CLI flags and automation, read the [CLI reference](reference/cli.md).

For how reports and evidence work, read [Core concepts](core-concepts.md).

To add an integration contract, read [Writing provider packs](extending/provider-packs.md).

To change the engine, start with [Development](development.md) and the [architecture decisions](architecture/README.md).
