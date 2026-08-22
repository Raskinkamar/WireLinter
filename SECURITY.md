# Security policy

WireLinter handles integration traffic that may contain credentials, personal data and business payloads. Treat traces, webhook captures and outbound API captures as sensitive until you have reviewed them.

## Reporting a security issue

Do not open a public issue containing webhook secrets, signing keys, access tokens, private endpoints, raw customer payloads or other confidential data.

For a vulnerability in WireLinter itself, use GitHub private vulnerability reporting for this repository when it is available. Include the affected command or component, the impact you observed and the smallest reproduction that does not disclose third-party secrets.

Ordinary provider-contract mistakes that do not expose sensitive data can be reported through a normal issue.

## Security boundaries

The current design relies on a few properties that should remain explicit:

- provider secrets resolved by trusted rule primitives are not written to Trace or Report artifacts;
- community packs are declarative and do not receive arbitrary Go, JavaScript or Python execution;
- external pack filesystem access is confined;
- external JSON Schema network resolution is disabled;
- parser and CEL execution are bounded;
- signature, secret-match and digest-match comparisons run in trusted code;
- the inbound listener and outbound proxy bind to loopback by default;
- inbound forwarding targets are loopback-only by default;
- the outbound proxy forwards only to its explicitly configured HTTP(S) target base;
- redirects are not followed by either forwarding client;
- request and response capture sizes are bounded;
- common credential-bearing headers and query parameters are redacted from outbound Trace evidence;
- Trace persistence is opt-in.

A change that weakens one of these boundaries for convenience should include an explicit design decision and tests.

See the [architecture decisions](docs/architecture/README.md), especially the records on evidence fidelity, secret resolution, local listener forwarding and outbound proxy acquisition.

## Outbound credential redaction

`wirelint proxy` must send the application's real credential to the provider. The forwarded request and the Trace are therefore intentionally different representations.

Common credential-bearing semantic headers and query values are replaced in Trace evidence. Authorization retains only its scheme, for example `Bearer <redacted>`, and the entry is marked `redacted: true`. A query that is altered for redaction is marked `queryFidelity: reconstructed`.

This is a best-effort safety boundary, not a data-loss-prevention system. Provider request and response bodies are not generically redacted because arbitrary body rewriting would require provider semantics and can destroy evidence fidelity. Bodies may contain credentials, personal data or business data.

## Captured traces

Before attaching a Trace to an issue or committing one as a fixture:

1. remove real credentials and tokens;
2. remove or replace personal/customer data;
3. check request and response bodies, query strings and headers;
4. do not assume outbound automatic redaction found every provider-specific secret location;
5. use deterministic test values when a signature fixture needs a secret.

Example fixtures in this repository use test secrets only.
