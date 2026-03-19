-- Wireshark Lua dissector for Ethereum Fulu consensus layer gossipsub messages.
-- Decodes snappy-compressed SSZ payloads from GossipSub PUBLISH messages.

if not libp2p or not libp2p._loaded then
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    dofile(script_dir .. "libp2p-common.lua")
    libp2p._loaded = true
end

local proto_eth = Proto("eth_consensus", "Ethereum Consensus")
proto_eth.fields = {}

---------------------------------------------------------------------------
-- Snappy decompression (block format, not framed)
---------------------------------------------------------------------------

local function snappy_decompress(s)
    if not s or #s == 0 then return nil, "empty input" end

    local ulen, vc = libp2p.decode_varint_str(s, 1)
    if vc == 0 or ulen == 0 then return nil, "bad varint" end

    local out = {}
    local out_len = 0
    local pos = 1 + vc

    while pos <= #s and out_len < ulen do
        local tag = s:byte(pos)
        pos = pos + 1
        local etype = bit.band(tag, 0x03)

        if etype == 0 then
            local lit_len_m1 = bit.rshift(tag, 2)
            local lit_len
            if lit_len_m1 < 60 then
                lit_len = lit_len_m1 + 1
            elseif lit_len_m1 == 60 then
                lit_len = s:byte(pos) + 1; pos = pos + 1
            elseif lit_len_m1 == 61 then
                lit_len = s:byte(pos) + s:byte(pos+1) * 256 + 1; pos = pos + 2
            elseif lit_len_m1 == 62 then
                lit_len = s:byte(pos) + s:byte(pos+1)*256 + s:byte(pos+2)*65536 + 1; pos = pos + 3
            else
                lit_len = s:byte(pos) + s:byte(pos+1)*256 + s:byte(pos+2)*65536 + s:byte(pos+3)*16777216 + 1; pos = pos + 4
            end
            if pos + lit_len - 1 > #s then return nil, "literal overrun" end
            table.insert(out, s:sub(pos, pos + lit_len - 1))
            out_len = out_len + lit_len
            pos = pos + lit_len

        elseif etype == 1 then
            local length = bit.band(bit.rshift(tag, 2), 0x07) + 4
            local offset = bit.lshift(bit.band(tag, 0xe0), 3) + s:byte(pos)
            pos = pos + 1
            if offset == 0 then return nil, "zero offset" end
            local full = table.concat(out)
            local src_start = #full - offset + 1
            if src_start < 1 then return nil, "offset underrun" end
            local copied = {}
            for j = 1, length do
                copied[j] = full:sub(src_start + ((j-1) % offset), src_start + ((j-1) % offset))
            end
            table.insert(out, table.concat(copied))
            out_len = out_len + length

        elseif etype == 2 then
            local length = bit.rshift(tag, 2) + 1
            local offset = s:byte(pos) + s:byte(pos+1) * 256
            pos = pos + 2
            if offset == 0 then return nil, "zero offset" end
            local full = table.concat(out)
            local src_start = #full - offset + 1
            if src_start < 1 then return nil, "offset underrun" end
            local copied = {}
            for j = 1, length do
                copied[j] = full:sub(src_start + ((j-1) % offset), src_start + ((j-1) % offset))
            end
            table.insert(out, table.concat(copied))
            out_len = out_len + length

        elseif etype == 3 then
            local length = bit.rshift(tag, 2) + 1
            local offset = s:byte(pos) + s:byte(pos+1)*256 + s:byte(pos+2)*65536 + s:byte(pos+3)*16777216
            pos = pos + 4
            if offset == 0 then return nil, "zero offset" end
            local full = table.concat(out)
            local src_start = #full - offset + 1
            if src_start < 1 then return nil, "offset underrun" end
            local copied = {}
            for j = 1, length do
                copied[j] = full:sub(src_start + ((j-1) % offset), src_start + ((j-1) % offset))
            end
            table.insert(out, table.concat(copied))
            out_len = out_len + length
        end
    end

    local result = table.concat(out)
    if #result < ulen then return nil, string.format("short: got %d want %d", #result, ulen) end
    return result:sub(1, ulen), nil
end

---------------------------------------------------------------------------
-- SSZ helpers (little-endian, 0-based offsets, 1-based strings)
---------------------------------------------------------------------------

local function ssz_uint64(s, offset)
    local i = offset + 1
    if i + 7 > #s then return 0 end
    local lo = s:byte(i) + s:byte(i+1)*256 + s:byte(i+2)*65536 + s:byte(i+3)*16777216
    local hi = s:byte(i+4) + s:byte(i+5)*256 + s:byte(i+6)*65536 + s:byte(i+7)*16777216
    return lo + hi * 4294967296
end

local function ssz_uint32(s, offset)
    local i = offset + 1
    if i + 3 > #s then return 0 end
    return s:byte(i) + s:byte(i+1)*256 + s:byte(i+2)*65536 + s:byte(i+3)*16777216
end

local function ssz_bytes_hex(s, offset, len)
    local i = offset + 1
    if i + len - 1 > #s then return "?" end
    return libp2p.bytes_to_hex(s:sub(i, i + len - 1))
end

local function short_hex(hex_str)
    if #hex_str <= 16 then return hex_str end
    return hex_str:sub(1, 8) .. "..." .. hex_str:sub(-8)
end

-- Count set bits in a raw string (for aggregation_bits / committee_bits).
local popcount_table = {}
for i = 0, 255 do
    local c = 0; local v = i
    while v > 0 do c = c + bit.band(v, 1); v = bit.rshift(v, 1) end
    popcount_table[i] = c
end

local function count_bits(s, offset, len)
    local count = 0
    for j = offset + 1, offset + len do
        if j > #s then break end
        count = count + popcount_table[s:byte(j)]
    end
    return count
end

-- For a Bitlist, the highest set bit is the length delimiter and shouldn't be counted.
-- Returns (bits_set, total_bits) for a Bitlist.
local function count_bitlist(s, offset, len)
    if len == 0 then return 0, 0 end
    -- Find the delimiter bit (highest set bit in the last byte)
    local last_byte = s:byte(offset + len)
    if not last_byte or last_byte == 0 then return count_bits(s, offset, len), len * 8 end
    -- Find position of highest bit
    local high = 7
    while high > 0 and bit.band(last_byte, bit.lshift(1, high)) == 0 do high = high - 1 end
    -- Total bits = (len-1)*8 + high (exclude the delimiter bit itself)
    local total = (len - 1) * 8 + high
    -- Count all set bits, subtract 1 for the delimiter
    local set = count_bits(s, offset, len) - 1
    return set, total
end

---------------------------------------------------------------------------
-- Checkpoint: epoch(8) + root(32) = 40 bytes
---------------------------------------------------------------------------

local function decode_checkpoint(s, offset, tree, label)
    local epoch = ssz_uint64(s, offset)
    local root = ssz_bytes_hex(s, offset + 8, 32)
    tree:add(string.format("%s: epoch=%d root=0x%s", label, epoch, short_hex(root)))
end

---------------------------------------------------------------------------
-- AttestationData: 128 bytes
-- slot(8) + committee_index(8) + beacon_block_root(32) + source(40) + target(40)
---------------------------------------------------------------------------

local function decode_attestation_data(s, offset, tree)
    tree:add(string.format("Slot: %d", ssz_uint64(s, offset)))
    tree:add(string.format("Committee Index: %d", ssz_uint64(s, offset + 8)))
    tree:add(string.format("Beacon Block Root: 0x%s", short_hex(ssz_bytes_hex(s, offset + 16, 32))))
    decode_checkpoint(s, offset + 48, tree, "Source")
    decode_checkpoint(s, offset + 88, tree, "Target")
end

---------------------------------------------------------------------------
-- BeaconBlockHeader: 112 bytes
-- slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_root(32)
---------------------------------------------------------------------------

local function decode_beacon_block_header(s, offset, tree)
    tree:add(string.format("Slot: %d", ssz_uint64(s, offset)))
    tree:add(string.format("Proposer Index: %d", ssz_uint64(s, offset + 8)))
    tree:add(string.format("Parent Root: 0x%s", short_hex(ssz_bytes_hex(s, offset + 16, 32))))
    tree:add(string.format("State Root: 0x%s", short_hex(ssz_bytes_hex(s, offset + 48, 32))))
    tree:add(string.format("Body Root: 0x%s", short_hex(ssz_bytes_hex(s, offset + 80, 32))))
end

---------------------------------------------------------------------------
-- SignedBeaconBlockFulu
-- SSZ: message_offset(4) + signature(96) = 100 bytes fixed
-- BeaconBlockFulu: slot(8) + proposer_index(8) + parent_root(32) + state_root(32) + body_offset(4)
---------------------------------------------------------------------------

local function decode_signed_beacon_block(s, tree)
    if #s < 100 then tree:add("(too short)"); return end
    local msg_offset = ssz_uint32(s, 0)
    local st = tree:add("SignedBeaconBlock")
    st:add(string.format("Signature: 0x%s", short_hex(ssz_bytes_hex(s, 4, 96))))

    if msg_offset + 84 > #s then st:add("(message too short)"); return end
    local bt = st:add("BeaconBlock")
    bt:add(string.format("Slot: %d", ssz_uint64(s, msg_offset)))
    bt:add(string.format("Proposer Index: %d", ssz_uint64(s, msg_offset + 8)))
    bt:add(string.format("Parent Root: 0x%s", short_hex(ssz_bytes_hex(s, msg_offset + 16, 32))))
    bt:add(string.format("State Root: 0x%s", short_hex(ssz_bytes_hex(s, msg_offset + 48, 32))))
    bt:add(string.format("Block Size: %d bytes (uncompressed)", #s))
end

---------------------------------------------------------------------------
-- SignedAggregateAttestationAndProofElectra
-- SSZ: message_offset(4) + signature(96) = 100 fixed
-- AggregateAttestationAndProofElectra:
--   aggregator_index(8) + aggregate_offset(4) + selection_proof(96) = 108 fixed
-- Aggregate (Attestation Electra):
--   aggregation_bits_offset(4) + data(128) + signature(96) + committee_bits_offset(4) = 232 fixed
---------------------------------------------------------------------------

local function decode_signed_aggregate(s, tree)
    if #s < 100 then tree:add("(too short)"); return end
    local msg_offset = ssz_uint32(s, 0)
    local st = tree:add("SignedAggregateAttestationAndProof")

    if msg_offset + 108 > #s then st:add("(message too short)"); return end
    st:add(string.format("Aggregator Index: %d", ssz_uint64(s, msg_offset)))
    st:add(string.format("Selection Proof: 0x%s", short_hex(ssz_bytes_hex(s, msg_offset + 12, 96))))

    local agg_offset_rel = ssz_uint32(s, msg_offset + 8)
    local att_abs = msg_offset + agg_offset_rel
    -- AttestationElectra fixed: agg_bits_offset(4) + data(128) + signature(96) + committee_bits(8) = 236
    if att_abs + 236 > #s then st:add("(attestation too short)"); return end

    local at = st:add("Aggregate Attestation")
    decode_attestation_data(s, att_abs + 4, at)
    at:add(string.format("Signature: 0x%s", short_hex(ssz_bytes_hex(s, att_abs + 132, 96))))

    -- committee_bits: Bitvector[64] = 8 bytes at att_abs + 228
    local cb_set = count_bits(s, att_abs + 228, 8)
    at:add(string.format("Committee Bits: %d committees, 0x%s", cb_set, ssz_bytes_hex(s, att_abs + 228, 8)))

    -- aggregation_bits: Bitlist at att_abs + agg_bits_offset_rel
    local agg_bits_off_rel = ssz_uint32(s, att_abs)
    local agg_bits_abs = att_abs + agg_bits_off_rel
    local agg_bits_len = #s - agg_bits_abs
    if agg_bits_len > 0 then
        local set, total = count_bitlist(s, agg_bits_abs, agg_bits_len)
        at:add(string.format("Aggregation Bits: %d/%d validators (%.0f%%), 0x%s",
            set, total, total > 0 and set/total*100 or 0,
            ssz_bytes_hex(s, agg_bits_abs, agg_bits_len)))
    end
end

---------------------------------------------------------------------------
-- SingleAttestation (Electra/Fulu): 240 bytes fixed
-- committee_index(8) + attester_index(8) + data(128) + signature(96)
---------------------------------------------------------------------------

local function decode_attestation(s, tree)
    if #s < 240 then tree:add(string.format("(too short: %d bytes)", #s)); return end
    local st = tree:add("SingleAttestation")
    st:add(string.format("Committee Index: %d", ssz_uint64(s, 0)))
    st:add(string.format("Attester Index: %d", ssz_uint64(s, 8)))
    decode_attestation_data(s, 16, st)
    st:add(string.format("Signature: 0x%s", short_hex(ssz_bytes_hex(s, 144, 96))))
end

---------------------------------------------------------------------------
-- SignedContributionAndProof: 360 bytes fixed (all fixed-size, no offsets)
-- ContributionAndProof(264) + signature(96)
--   aggregator_index(8) + SyncCommitteeContribution(160) + selection_proof(96)
--     slot(8) + block_root(32) + subcommittee_index(8) + aggregation_bits(16) + signature(96)
---------------------------------------------------------------------------

local function decode_signed_contribution(s, tree)
    if #s < 360 then tree:add(string.format("(too short: %d bytes)", #s)); return end
    local st = tree:add("SignedContributionAndProof")
    st:add(string.format("Aggregator Index: %d", ssz_uint64(s, 0)))

    local ct = st:add("SyncCommitteeContribution")
    ct:add(string.format("Slot: %d", ssz_uint64(s, 8)))
    ct:add(string.format("Block Root: 0x%s", short_hex(ssz_bytes_hex(s, 16, 32))))
    ct:add(string.format("Subcommittee Index: %d", ssz_uint64(s, 48)))

    -- aggregation_bits: Bitvector[128] = 16 bytes at offset 56
    local ab_set = count_bits(s, 56, 16)
    ct:add(string.format("Aggregation Bits: %d/128 validators (%.0f%%), 0x%s",
        ab_set, ab_set/128*100, ssz_bytes_hex(s, 56, 16)))

    st:add(string.format("Selection Proof: 0x%s", short_hex(ssz_bytes_hex(s, 168, 96))))
    st:add(string.format("Signature: 0x%s", short_hex(ssz_bytes_hex(s, 264, 96))))
end

---------------------------------------------------------------------------
-- DataColumnSidecar: 232 bytes fixed part
-- index(8) + column_offset(4) + kzg_commitments_offset(4) + kzg_proofs_offset(4) +
-- signed_block_header(208) + kzg_commitments_inclusion_proof_offset(4)
---------------------------------------------------------------------------

local function decode_data_column_sidecar(s, tree)
    if #s < 232 then tree:add("(too short)"); return end
    local st = tree:add("DataColumnSidecar")
    st:add(string.format("Column Index: %d", ssz_uint64(s, 0)))
    st:add(string.format("Sidecar Size: %d bytes (uncompressed)", #s))

    local hdr_tree = st:add("Signed Block Header")
    decode_beacon_block_header(s, 20, hdr_tree)  -- after index(8) + 3 offsets(12)
    hdr_tree:add(string.format("Signature: 0x%s", short_hex(ssz_bytes_hex(s, 132, 96))))
end

---------------------------------------------------------------------------
-- Topic to decoder mapping
---------------------------------------------------------------------------

local topic_decoders = {
    ["beacon_block"]                            = decode_signed_beacon_block,
    ["beacon_aggregate_and_proof"]              = decode_signed_aggregate,
    ["beacon_attestation"]                      = decode_attestation,
    ["sync_committee_contribution_and_proof"]   = decode_signed_contribution,
    ["data_column_sidecar"]                     = decode_data_column_sidecar,
}

local function get_decoder(topic)
    if not topic then return nil end
    for prefix, decoder in pairs(topic_decoders) do
        if topic:find(prefix, 1, true) then return decoder end
    end
    return nil
end

---------------------------------------------------------------------------
-- Post-dissector
---------------------------------------------------------------------------

function proto_eth.dissector(tvb, pinfo, tree)
    local streams = libp2p.process_streams(pinfo)
    for _, st in ipairs(streams) do
        if not st.payload or not st.protocol or not st.protocol:find("meshsub") then goto next end

        local payload = st.payload
        local prev = st.prev_payload_len
        local pos = 1

        while pos <= #payload do
            local rpc_len, consumed = libp2p.decode_varint_str(payload, pos)
            if consumed == 0 or rpc_len == 0 or pos + consumed + rpc_len - 1 > #payload then break end
            local rpc_start = pos + consumed
            local rpc_end = rpc_start + rpc_len - 1

            if rpc_end > prev then
                libp2p.pb_each_str(payload, rpc_start, rpc_end, function(fnum, wtype, dstart, dlen, val)
                    if fnum ~= 2 or wtype ~= 2 then return end

                    local topic, data_str = nil, nil
                    libp2p.pb_each_str(payload, dstart, dstart + dlen - 1, function(fn2, wt2, ds2, dl2, v2)
                        if fn2 == 2 and wt2 == 2 then data_str = payload:sub(ds2, ds2 + dl2 - 1) end
                        if fn2 == 4 and wt2 == 2 then topic = payload:sub(ds2, ds2 + dl2 - 1) end
                    end)

                    if not data_str or not topic then return end
                    local decoder = get_decoder(topic)
                    if not decoder then return end

                    local ssz_data, err = snappy_decompress(data_str)
                    if not ssz_data then
                        local et = tree:add(proto_eth, tvb(), "Ethereum Consensus [" .. topic .. "]")
                        et:add("Snappy decompress error: " .. (err or "unknown"))
                        return
                    end

                    local et = tree:add(proto_eth, tvb(), "Ethereum Consensus [" .. topic .. "]")
                    et:add(string.format("Compressed: %d bytes, Uncompressed: %d bytes", #data_str, #ssz_data))
                    decoder(ssz_data, et)
                end)
            end

            pos = rpc_end + 1
        end
        ::next::
    end
end

register_postdissector(proto_eth)
