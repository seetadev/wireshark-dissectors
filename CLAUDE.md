# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Wireshark/tshark Lua dissector plugins for decoding libp2p and Ethereum consensus layer protocols over QUIC. Includes Go test programs for generating captures and a guide for patching go-libp2p clients to export TLS keys.

## Testing Dissectors with tshark

The dissectors are loaded via `-X lua_script:`. Only `libp2p-identify.lua` and `libp2p-gossipsub.lua` need to be specified — they auto-load `libp2p-common.lua` via `dofile`. `eth-consensus.lua` is optional and adds Ethereum SSZ decoding.

```bash
# Basic: libp2p protocols only
tshark -r capture.pcap \
  -o tls.keylog_file:keys.log \
  -d udp.port==PORT,quic \
  -X lua_script:libp2p-identify.lua \
  -X lua_script:libp2p-gossipsub.lua

# Full: with Ethereum consensus message decoding
tshark -r capture.pcap \
  -o tls.keylog_file:keys.log \
  -d udp.port==PORT,quic \
  -X lua_script:libp2p-identify.lua \
  -X lua_script:libp2p-gossipsub.lua \
  -X lua_script:eth-consensus.lua
```

Common QUIC ports: 4242 (local test), 9001 (eth-probe), 13001 (Prysm).

## Architecture

### Dissector Plugin Stack

All plugins are Wireshark Lua post-dissectors that hook into the `quic.stream_data` field after Wireshark's built-in QUIC dissector decrypts the traffic.

**`libp2p-common.lua`** — Shared layer loaded by all other plugins. Provides:
- QUIC stream reassembly across frames (`process_streams()`). Accumulates `quic.stream_data` per connection+stream, handles out-of-order delivery and retransmissions using `quic.stream.offset`, tracks contiguous byte ranges to avoid parsing gaps.
- Multistream-select negotiation parsing — identifies the libp2p protocol for each stream (e.g., `/ipfs/id/1.0.0`, `/meshsub/1.3.0`).
- Varint decoding, protobuf field iteration, multiaddr formatting.

**`libp2p-identify.lua`** — Decodes `/ipfs/id/1.0.0` and `/ipfs/id/push/1.0.0`. Parses the Identify protobuf (public key, listen addresses, protocols, agent version, observed address).

**`libp2p-gossipsub.lua`** — Decodes `/meshsub/1.x.0` and `/floodsub/1.0.0`. Parses varint-length-prefixed RPC protobuf messages: subscriptions, publish (with data length), and control messages (IHAVE, IWANT, GRAFT, PRUNE, IDONTWANT).

**`eth-consensus.lua`** — Decodes Ethereum Fulu-era consensus messages inside gossipsub PUBLISH payloads. Implements snappy decompression in pure Lua, then decodes SSZ fixed fields for: `SignedBeaconBlock`, `SignedAggregateAttestationAndProofElectra` (with aggregation bits and committee bits), `SingleAttestation`, `SignedContributionAndProof` (with sync committee aggregation bits), and `DataColumnSidecar`.

### Data Flow

```
QUIC packet → Wireshark QUIC dissector (decrypts with TLS keys)
  → quic.stream_data field
  → libp2p-common.lua: reassemble stream, parse multistream-select
  → libp2p-identify.lua / libp2p-gossipsub.lua: decode protocol messages
  → eth-consensus.lua: snappy decompress → SSZ decode publish payloads
```

### Key Design Decisions

- **No synthetic Tvbs**: Earlier versions created `ByteArray:tvb()` objects for tree items, which caused crashes in Wireshark GUI (`except_pop` assertion). All tree items use `tree:add("text")` or `tree:add(proto, tvb(), "text")` with the frame's own tvb.
- **Connection-scoped stream keys**: Stream IDs are namespaced by `quic.connection.number` since different QUIC connections reuse the same stream ID space.
- **Offset-based dedup**: Uses `quic.stream.offset` when array lengths match (1:1 with stream IDs), falls back to `high_water` tracking otherwise. Random-access buffer placement handles out-of-order and retransmitted STREAM frames. Only the contiguous byte range from offset 0 is exposed for parsing.
- **Frame result caching**: `process_streams()` caches per-frame results so multiple dissectors can call it without double-accumulating data.
- **tshark single-pass only**: The `-2` (two-pass) mode and Wireshark GUI's second pass cannot access `quic.stream_data` from Lua field extractors, so dissection only works in single-pass mode.
