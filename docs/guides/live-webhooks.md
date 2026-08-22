# Debugging live webhooks

`wirelint listen` puts a local capture-and-lint step in front of your application. It is intended for development and diagnosis, not as production webhook infrastructure.

## Basic use

```bash
wirelint listen stripe http://127.0.0.1:3000/webhooks/stripe
```

The default listener address is `127.0.0.1:4545`.

A delivery flows through WireLinter before it reaches your application:

```text
provider / local forwarder
          |
          v
   WireLinter :4545
          |
          v
   local application
```

The listener captures the inbound request, forwards the exact body bytes, captures the application response, then schedules linting. Rule evaluation is not added to the provider acknowledgement path.

## Secrets

Provider packs declare logical secret references that map to environment variables. If a required verification secret is absent, rules that depend on it report `open` rather than guessing.

For example:

```bash
export STRIPE_WEBHOOK_SECRET='whsec_...'
```

WireLinter does not write configured secrets into the Trace or Report.

## Saving traces

Trace persistence is disabled by default because webhook bodies can contain personal or sensitive data.

Enable it explicitly:

```bash
wirelint listen stripe http://127.0.0.1:3000/webhooks/stripe \
  --save-dir ./traces
```

Saved trace files are created with restrictive permissions and are not overwritten when a Trace ID already exists.

Review saved payloads before committing them to a repository.

## Listener and forwarding safety

WireLinter defaults to loopback for both the listening socket and forwarding target.

Binding to a non-loopback interface requires:

```text
--allow-public-listen
```

Forwarding to a non-loopback target requires:

```text
--allow-remote-forward
```

These flags are deliberately separate. Needing one does not automatically enable the other.

Redirects are not followed by the forwarding client.

## Body limits

The listener bounds the inbound request body and captured response body. Override the defaults only when the provider requires it:

```bash
wirelint listen \
  --provider <id> \
  --forward-to http://127.0.0.1:3000/webhook \
  --max-body-bytes <bytes> \
  --max-response-capture-bytes <bytes>
```

An exact raw body is important for providers that sign the bytes sent on the wire. Parsing and re-serializing JSON before verification can change those bytes.

## External packs

Use a local pack directory instead of a bundled provider with `--pack`:

```bash
wirelint listen \
  --pack ./packs/my-provider \
  --forward-to http://127.0.0.1:3000/webhook
```

`--provider` and `--pack` are mutually exclusive.

## Troubleshooting

If a signature rule reports `open`, first check whether the pack's environment variable is set. If it reports a mismatch, confirm that WireLinter is receiving the provider's original body rather than a body that has already been parsed and rebuilt by another proxy.

If acknowledgement rules fail, the relevant response is the response returned by your local application, not WireLinter's later diagnostic work.
