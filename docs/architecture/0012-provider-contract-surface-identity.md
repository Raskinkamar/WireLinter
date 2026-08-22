# ADR 0012 — Provider IDs identify diagnostic delivery contracts

Status: **Accepted for implementation**

## Context

A vendor name is not always enough to identify the protocol semantics that WireLinter should evaluate.

Shopify webhook subscriptions can deliver through multiple transports, including HTTPS, Google Cloud Pub/Sub, and Amazon EventBridge. HTTPS deliveries carry HTTP-specific headers and use `X-Shopify-Hmac-SHA256`; cloud event-bus deliveries have different transport/authentication semantics.

Mercado Pago likewise exposes materially different notification contracts. Webhooks and legacy IPN differ in origin-verification guarantees, and product-specific notification surfaces can have their own configuration and signing details.

Treating a brand logo as one universal provider contract creates a dangerous failure mode: a rule can be internally correct yet be applied to the wrong delivery surface.

## Decision

An official bundled pack ID identifies a **concrete diagnostic contract**, not merely a vendor brand.

When a vendor has only one supported contract, the short vendor ID remains acceptable:

```text
github
stripe
```

When a vendor exposes multiple materially different delivery surfaces, the pack ID must disambiguate the supported surface:

```text
shopify-https
```

Future examples could include IDs such as:

```text
shopify-eventbridge
shopify-pubsub
mercadopago-webhooks
mercadopago-ipn
```

Those examples are illustrative only; an ID is created only after that exact surface has been researched and implemented.

A pack MUST NOT claim the umbrella vendor ID if doing so would imply that rules apply to delivery surfaces with different authentication, acknowledgement, payload, or transport semantics.

## Why encode the surface in the existing ID

The current public Trace and Report contracts already bind evidence to `provider`, and the loader enforces that the Trace provider matches the selected pack ID.

Encoding the concrete contract in the ID therefore provides an immediate safety property without adding a second selector or changing the Trace schema:

```text
trace.provider = shopify-https
pack.id        = shopify-https
```

A Shopify EventBridge event cannot accidentally be evaluated as an HTTPS webhook unless the evidence is mislabeled at acquisition time.

This is preferable to introducing a new `surface` field or Pack Protocol version before there is a demonstrated need for runtime behavior that cannot be represented by contract IDs.

## Metadata

Packs may additionally record human/tooling metadata such as:

```yaml
metadata:
  vendor: shopify
  surface: https-webhook
```

Metadata does not replace the contract identity and is not trusted for rule selection. The pack ID remains the binding identity used by Trace evaluation.

## Consequences

### Positive

- no provider-specific core branch is required;
- existing Trace/Report schemas remain stable;
- CLI selection is explicit (`--provider shopify-https`);
- documentation cannot reasonably imply EventBridge/PubSub support from an HTTPS-only pack;
- additional surfaces can be shipped independently and versioned independently.

### Tradeoff

Users see a more specific provider ID instead of only a brand name. This is intentional: protocol correctness is more important than logo-count simplicity.

If future UX needs grouping by vendor, the CLI can derive a richer catalog from typed or validated metadata without changing the diagnostic identity contract.
