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

## Running Tests

```bash
make test
```

Runs `test.sh` which verifies all three dissector layers against pcaps in `test-data/`. Requires `tshark`.

## Writing Ad-Hoc Analysis Scripts

To answer questions about captured traffic (bandwidth per topic, duplicate rates, message timing, etc.), write a temporary Lua post-dissector that uses the shared dissector APIs. The pattern:

```lua
-- Load the shared library
if not libp2p or not libp2p._loaded then
    dofile("/path/to/libp2p-common.lua")
    libp2p._loaded = true
end

-- For snappy/SSZ, inline or dofile eth-consensus.lua functions as needed.

local my_stats = {}

local p = Proto("my_analysis", "analysis")
function p.dissector(tvb, pinfo, tree)
    local streams = libp2p.process_streams(pinfo)
    for _, st in ipairs(streams) do
        if not st.payload or not st.protocol or not st.protocol:find("meshsub") then goto next end
        local payload = st.payload
        local prev = st.prev_payload_len
        local pos = 1
        -- Iterate varint-length-prefixed RPC messages
        while pos <= #payload do
            local rpc_len, consumed = libp2p.decode_varint_str(payload, pos)
            if consumed == 0 or rpc_len == 0 or pos + consumed + rpc_len - 1 > #payload then break end
            local rpc_start = pos + consumed
            local rpc_end = rpc_start + rpc_len - 1
            if rpc_end > prev then  -- only process new RPCs
                -- Parse RPC protobuf: field 1=subscriptions, 2=publish, 3=control
                libp2p.pb_each_str(payload, rpc_start, rpc_end, function(fnum, wtype, dstart, dlen, val)
                    if fnum == 2 and wtype == 2 then  -- publish message
                        local topic, data_str = nil, nil
                        libp2p.pb_each_str(payload, dstart, dstart+dlen-1, function(fn2,wt2,ds2,dl2,v2)
                            if fn2 == 2 and wt2 == 2 then data_str = payload:sub(ds2, ds2+dl2-1) end
                            if fn2 == 4 and wt2 == 2 then topic = payload:sub(ds2, ds2+dl2-1) end
                        end)
                        -- Accumulate stats here using topic, #data_str, etc.
                        -- To access SSZ fields: snappy_decompress(data_str) then read at byte offsets
                    end
                end)
            end
            pos = rpc_end + 1
        end
        ::next::
    end
end

-- Use a Listener tap to print results after all frames are processed
local tap = Listener.new("frame")
function tap.draw()
    io.stderr:write("Results:\n")
    -- Print my_stats here
end
function tap.reset() end

register_postdissector(p)
```

Run with: `tshark -r capture.pcap -o tls.keylog_file:keys.log -d udp.port==PORT,quic -X lua_script:libp2p-identify.lua -X lua_script:libp2p-gossipsub.lua -X lua_script:/tmp/my_analysis.lua -q`

The `-q` flag suppresses per-packet output; the tap's `draw()` fires at the end.

### Key APIs for Analysis Scripts

- **`libp2p.process_streams(pinfo)`** — Returns list of `{stream_id, protocol, payload, prev_payload_len}`. Call once per frame; cached automatically.
- **`libp2p.decode_varint_str(s, idx)`** — Decode varint from 1-based string index. Returns `(value, bytes_consumed)`.
- **`libp2p.pb_each_str(s, from, to, visitor)`** — Iterate protobuf fields in string `s[from..to]`. Visitor receives `(field_number, wire_type, data_start, data_len, varint_value)`.
- **`libp2p.bytes_to_hex(s)`** — Raw string to hex.
- **`libp2p.format_multiaddr(s)`** — Raw multiaddr bytes to human string.

### Gossipsub RPC Protobuf Fields

- Field 1 (subscriptions): `SubOpts` — field 1=subscribe(bool), field 2=topicid(string)
- Field 2 (publish): `Message` — field 1=from, field 2=data, field 3=seqno, field 4=topic, field 5=signature
- Field 3 (control): `ControlMessage` — field 1=IHAVE, 2=IWANT, 3=GRAFT, 4=PRUNE, 5=IDONTWANT

### SSZ Byte Offsets (Fulu era)

**SignedAggregateAttestationAndProofElectra**: outer `msg_offset = u32(ssz, 0)`, then at `msg_offset`: `aggregator_index(u64, +0)`, `agg_offset_rel(u32, +8)`, `selection_proof(96B, +12)`. Attestation at `msg_offset + agg_offset_rel`: `agg_bits_offset(u32, +0)`, `AttestationData(128B, +4)`, `signature(96B, +132)`, `committee_bits(8B, +228)`. Aggregation bits (Bitlist) at attestation + agg_bits_offset.

**SingleAttestation** (240B fixed): `committee_index(u64, +0)`, `attester_index(u64, +8)`, `AttestationData(128B, +16)`, `signature(96B, +144)`.

**AttestationData** (128B): `slot(u64, +0)`, `committee_index(u64, +8)`, `beacon_block_root(32B, +16)`, `source(40B, +48)`, `target(40B, +88)`. Checkpoint (40B): `epoch(u64, +0)`, `root(32B, +8)`.

**SignedContributionAndProof** (360B fixed): `aggregator_index(u64, +0)`, SyncCommitteeContribution at +8: `slot(u64, +8)`, `block_root(32B, +16)`, `subcommittee_index(u64, +48)`, `aggregation_bits(16B, +56)`, `contribution_sig(96B, +72)`. `selection_proof(96B, +168)`, `outer_sig(96B, +264)`.

**DataColumnSidecar**: `index(u64, +0)`, 3 offsets(12B), `SignedBeaconBlockHeader(208B, +20)`. Header: `slot(u64, +0)`, `proposer_index(u64, +8)`, `parent_root(32B, +16)`, `state_root(32B, +48)`, `body_root(32B, +80)`, `signature(96B, +112)`.

**SignedBeaconBlock**: `msg_offset(u32, +0)`, `signature(96B, +4)`. At msg_offset: `slot(u64, +0)`, `proposer_index(u64, +8)`, `parent_root(32B, +16)`, `state_root(32B, +48)`.

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
