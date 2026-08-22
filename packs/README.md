# Provider packs

This directory contains the provider contracts bundled into WireLinter.

Each top-level directory is one concrete contract. The directory name is the provider ID printed by:

```bash
wirelint providers
```

Do not treat a directory as a claim that every integration surface from that vendor is supported. Authentication modes, setup handshakes and transports may have separate IDs when their protocol behavior differs.

## Adding a pack

Read [Writing provider packs](../docs/extending/provider-packs.md) before adding or changing a contract.

Provider behavior must be grounded in primary provider documentation or an official SDK. The Go core should remain provider-neutral.

Valid pack directories are embedded and discovered automatically; there is no provider-name registry to update by hand.
