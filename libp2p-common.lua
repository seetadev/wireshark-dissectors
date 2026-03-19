-- Shared utilities for libp2p Wireshark dissectors.
-- Provides varint decoding, multistream-select parsing, per-stream reassembly,
-- and multiaddr formatting.

libp2p = libp2p or {}

---------------------------------------------------------------------------
-- Varint (operates on raw Lua strings, 1-based indexing)
---------------------------------------------------------------------------

function libp2p.decode_varint_str(s, idx)
    if not s or idx < 1 or idx > #s then return 0, 0 end
    local value = 0
    local shift = 0
    local pos = idx
    while pos <= #s do
        local b = s:byte(pos)
        if not b then return 0, pos - idx end
        value = bit.bor(value, bit.lshift(bit.band(b, 0x7F), shift))
        pos = pos + 1
        shift = shift + 7
        if bit.band(b, 0x80) == 0 then
            return value, pos - idx
        end
        if shift >= 35 then break end -- varint too long (>5 bytes for 32-bit)
    end
    return value, pos - idx
end

---------------------------------------------------------------------------
-- Protobuf helper (1-based string indexing)
---------------------------------------------------------------------------

function libp2p.pb_each_str(s, from, to, visitor)
    if not s or from < 1 or to > #s or from > to then return end
    local pos = from
    while pos <= to do
        local tag, tc = libp2p.decode_varint_str(s, pos)
        if tc == 0 then break end
        pos = pos + tc
        local field_number = bit.rshift(tag, 3)
        local wire_type = bit.band(tag, 0x07)
        if wire_type == 0 then
            local val, vc = libp2p.decode_varint_str(s, pos)
            if vc == 0 then break end
            visitor(field_number, 0, pos, vc, val)
            pos = pos + vc
        elseif wire_type == 2 then
            local dlen, dc = libp2p.decode_varint_str(s, pos)
            if dc == 0 then break end
            pos = pos + dc
            if pos + dlen - 1 > to then break end
            visitor(field_number, 2, pos, dlen, nil)
            pos = pos + dlen
        else
            break
        end
    end
end

---------------------------------------------------------------------------
-- Hex formatting
---------------------------------------------------------------------------

function libp2p.bytes_to_hex(s)
    local hex = {}
    for i = 1, #s do hex[i] = string.format("%02x", s:byte(i)) end
    return table.concat(hex)
end

---------------------------------------------------------------------------
-- Multiaddr formatting
---------------------------------------------------------------------------

local multiaddr_codecs = {
    [4]   = { name = "ip4",     size = 4,  fmt = function(s, i) return string.format("%d.%d.%d.%d", s:byte(i), s:byte(i+1), s:byte(i+2), s:byte(i+3)) end },
    [6]   = { name = "tcp",     size = 2,  fmt = function(s, i) return tostring(s:byte(i)*256 + s:byte(i+1)) end },
    [273] = { name = "udp",     size = 2,  fmt = function(s, i) return tostring(s:byte(i)*256 + s:byte(i+1)) end },
    [461] = { name = "quic-v1", size = 0 },
}

function libp2p.format_multiaddr(s)
    local parts = {}
    local pos = 1
    while pos <= #s do
        local code, consumed = libp2p.decode_varint_str(s, pos)
        pos = pos + consumed
        local codec = multiaddr_codecs[code]
        if codec then
            if codec.size > 0 and pos + codec.size - 1 <= #s then
                table.insert(parts, "/" .. codec.name .. "/" .. codec.fmt(s, pos))
                pos = pos + codec.size
            elseif codec.size == 0 then
                table.insert(parts, "/" .. codec.name)
            else break end
        else
            table.insert(parts, string.format("/0x%x/...", code))
            break
        end
    end
    return table.concat(parts, "")
end

---------------------------------------------------------------------------
-- Stream reassembly (post-dissector compatible, multi-pass safe)
--
-- We pair quic.stream.stream_id with quic.stream_data by index. Both are
-- emitted once per STREAM frame in the packet, so they align 1:1.
--
-- We do NOT use quic.stream.offset because it is only emitted when the
-- QUIC STREAM frame's O(ffset) bit is set (i.e. offset > 0). When a
-- packet contains multiple STREAM frames and some have offset=0, the
-- offset array is shorter than the id/data arrays and the pairing breaks.
-- Instead we simply append each chunk to the stream buffer in wire order.
-- This is correct as long as Wireshark feeds us frames in order, which
-- it does for post-dissectors.
---------------------------------------------------------------------------

-- Per-stream state: { buf, protocol, payload_offset }
libp2p._streams = {}

-- Per-frame cached stable data (survives across passes):
--   frame_number -> list of { stream_id, protocol, payload, prev_payload_len, buf_hex }
-- buf_hex is the hex string for recreating a Tvb (Tvbs expire between passes).
libp2p._frame_results = {}

-- Track the highest frame number seen to detect pass resets.
libp2p._max_frame = 0

-- Field extractors (no offset — see comment above)
libp2p._f_sid   = Field.new("quic.stream.stream_id")
libp2p._f_sdata = Field.new("quic.stream_data")
libp2p._f_conn  = Field.new("quic.connection.number")

local function parse_multistream(buf)
    if not buf or #buf == 0 then return nil, 1 end
    local pos = 1
    local found_ms = false
    while pos <= #buf do
        local msg_len, consumed = libp2p.decode_varint_str(buf, pos)
        if consumed == 0 or msg_len == 0 or pos + consumed + msg_len - 1 > #buf then
            return nil, pos
        end
        local msg = buf:sub(pos + consumed, pos + consumed + msg_len - 1):gsub("\n$", "")
        if msg == "/multistream/1.0.0" then
            found_ms = true
        elseif found_ms and msg:match("^/") then
            return msg, pos + consumed + msg_len
        else
            return nil, pos
        end
        pos = pos + consumed + msg_len
    end
    return nil, pos
end


function libp2p.process_streams(pinfo)
    local frame_num = pinfo.number

    -- Detect pass reset.
    if frame_num <= libp2p._max_frame and frame_num == 1 then
        libp2p._streams = {}
    end
    if frame_num > libp2p._max_frame then
        libp2p._max_frame = frame_num
    end

    -- Return cached results from a prior pass.
    local cached = libp2p._frame_results[frame_num]
    if cached then return cached end

    -- First pass: read fields and accumulate stream data.
    local ids   = { libp2p._f_sid() }
    local datas = { libp2p._f_sdata() }
    local conns = { libp2p._f_conn() }

    if #ids == 0 then
        libp2p._frame_results[frame_num] = {}
        return {}
    end

    -- Connection number is per-packet (same for all STREAM frames in one packet).
    local conn_num = conns[1] and tostring(conns[1].value) or "?"

    local results = {}
    local stable = {}

    for i, id_fld in ipairs(ids) do
        local sid = id_fld.value
        local data_fld = datas[i]
        if not data_fld or not data_fld.range then goto next end

        local key = conn_num .. ":" .. tostring(sid)
        local state = libp2p._streams[key]
        if not state then
            state = { buf = "", protocol = nil, payload_offset = 0 }
            libp2p._streams[key] = state
        end

        -- Record previous payload length before appending new data.
        local prev_pl = 0
        if state.protocol and state.payload_offset > 0 and state.payload_offset <= #state.buf then
            prev_pl = #state.buf - state.payload_offset + 1
        end

        -- Append data to the stream buffer (wire order).
        state.buf = state.buf .. data_fld.range:raw()

        -- Parse multistream-select if not yet done.
        if not state.protocol then
            local proto, after = parse_multistream(state.buf)
            if proto then
                state.protocol = proto
                state.payload_offset = after
            end
        end

        -- Extract application payload.
        local payload = nil
        if state.protocol and state.payload_offset > 0 and state.payload_offset <= #state.buf then
            payload = state.buf:sub(state.payload_offset)
        end

        local entry = {
            stream_id = sid,
            protocol = state.protocol,
            payload = payload,
            prev_payload_len = prev_pl,
        }
        table.insert(stable, entry)
        table.insert(results, entry)

        ::next::
    end

    libp2p._frame_results[frame_num] = stable
    return results
end
