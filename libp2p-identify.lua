-- Wireshark Lua dissector for libp2p Identify protocol (/ipfs/id/1.0.0)
-- Understands multistream-select negotiation framing.

local proto_identify = Proto("libp2p_identify", "libp2p Identify")

-- Identify protobuf fields (field numbers from identify.proto)
local f_publickey     = ProtoField.bytes("libp2p_identify.public_key", "Public Key")
local f_listen_addr   = ProtoField.string("libp2p_identify.listen_addr", "Listen Address")
local f_protocol      = ProtoField.string("libp2p_identify.protocol", "Protocol")
local f_observed_addr = ProtoField.string("libp2p_identify.observed_addr", "Observed Address")
local f_protocol_ver  = ProtoField.string("libp2p_identify.protocol_version", "Protocol Version")
local f_agent_ver     = ProtoField.string("libp2p_identify.agent_version", "Agent Version")
local f_signed_record = ProtoField.bytes("libp2p_identify.signed_peer_record", "Signed Peer Record")

-- Multistream fields
local f_ms_protocol   = ProtoField.string("libp2p_identify.ms_protocol", "Multistream Protocol")

proto_identify.fields = {
    f_publickey, f_listen_addr, f_protocol, f_observed_addr,
    f_protocol_ver, f_agent_ver, f_signed_record, f_ms_protocol,
}

-- Field extractors
local f_quic_stream_data = Field.new("quic.stream_data")

-- Decode a protobuf varint from a Tvb starting at offset.
-- Returns value, bytes_consumed.
local function decode_varint(tvb, offset)
    local value = 0
    local shift = 0
    local pos = offset
    local len = tvb:len()
    while pos < len do
        local b = tvb(pos, 1):uint()
        value = bit.bor(value, bit.lshift(bit.band(b, 0x7F), shift))
        pos = pos + 1
        shift = shift + 7
        if bit.band(b, 0x80) == 0 then
            return value, pos - offset
        end
    end
    return value, pos - offset
end

-- Multiaddr protocol codes
local multiaddr_codecs = {
    [4]   = { name = "ip4",     size = 4,  fmt = function(tvb, off) return string.format("%d.%d.%d.%d", tvb(off,1):uint(), tvb(off+1,1):uint(), tvb(off+2,1):uint(), tvb(off+3,1):uint()) end },
    [6]   = { name = "tcp",     size = 2,  fmt = function(tvb, off) return tostring(tvb(off,2):uint()) end },
    [273] = { name = "udp",     size = 2,  fmt = function(tvb, off) return tostring(tvb(off,2):uint()) end },
    [461] = { name = "quic-v1", size = 0 },
}

local function format_multiaddr(tvb, offset, length)
    local parts = {}
    local pos = offset
    local endpos = offset + length
    while pos < endpos do
        local code, consumed = decode_varint(tvb, pos)
        pos = pos + consumed
        local codec = multiaddr_codecs[code]
        if codec then
            if codec.size > 0 then
                local val = codec.fmt(tvb, pos)
                table.insert(parts, "/" .. codec.name .. "/" .. val)
                pos = pos + codec.size
            elseif codec.size == 0 then
                table.insert(parts, "/" .. codec.name)
            end
        else
            table.insert(parts, string.format("/0x%x/...", code))
            break
        end
    end
    return table.concat(parts, "")
end

-- Parse the Identify protobuf message and add to tree.
local function dissect_identify_pb(tvb, offset, length, tree)
    local pos = offset
    local endpos = offset + length
    while pos < endpos do
        local tag, consumed = decode_varint(tvb, pos)
        pos = pos + consumed
        local field_number = bit.rshift(tag, 3)
        local wire_type = bit.band(tag, 0x07)

        if wire_type == 0 then
            -- Varint - skip
            local _, vc = decode_varint(tvb, pos)
            pos = pos + vc
        elseif wire_type == 2 then
            -- Length-delimited
            local dlen, dc = decode_varint(tvb, pos)
            pos = pos + dc
            if pos + dlen > endpos then break end
            if field_number == 1 then
                tree:add(f_publickey, tvb(pos, dlen))
            elseif field_number == 2 then
                local addr_str = format_multiaddr(tvb, pos, dlen)
                tree:add(f_listen_addr, tvb(pos, dlen), addr_str)
            elseif field_number == 3 then
                tree:add(f_protocol, tvb(pos, dlen))
            elseif field_number == 4 then
                local addr_str = format_multiaddr(tvb, pos, dlen)
                tree:add(f_observed_addr, tvb(pos, dlen), addr_str)
            elseif field_number == 5 then
                tree:add(f_protocol_ver, tvb(pos, dlen))
            elseif field_number == 6 then
                tree:add(f_agent_ver, tvb(pos, dlen))
            elseif field_number == 8 then
                tree:add(f_signed_record, tvb(pos, dlen))
            end
            pos = pos + dlen
        else
            break
        end
    end
end

-- Post-dissector: runs on every frame after normal dissection.
function proto_identify.dissector(tvb, pinfo, tree)
    -- Get all quic.stream_data field values in this frame
    local fields = { f_quic_stream_data() }
    if #fields == 0 then return end

    for _, fld in ipairs(fields) do
        local data_tvb = fld.range
        if data_tvb and data_tvb:len() >= 20 then
            -- Check for multistream-select header: first varint should be 0x13 (19),
            -- followed by "/multistream/1.0.0\n"
            local first_byte = data_tvb(0, 1):uint()
            if first_byte == 0x13 then
                local header = data_tvb(1, 19):string()
                if header == "/multistream/1.0.0\n" then
                    -- Check if this contains /ipfs/id/1.0.0
                    local raw = data_tvb():raw()
                    if raw:find("/ipfs/id/1.0.0") then
                        local subtree = tree:add(proto_identify, data_tvb, "libp2p Identify")

                        -- Parse multistream lines
                        local pos = 0
                        local len = data_tvb:len()
                        local found_identify = false

                        while pos < len do
                            local msg_len, consumed = decode_varint(data_tvb, pos)
                            if msg_len == 0 or pos + consumed + msg_len > len then
                                break
                            end

                            local msg_start = pos + consumed
                            local msg_str = data_tvb(msg_start, msg_len):string()
                            local display = msg_str:gsub("\n$", "")

                            if display:match("^/") then
                                subtree:add(f_ms_protocol, data_tvb(pos, consumed + msg_len), display)
                                if display == "/ipfs/id/1.0.0" then
                                    found_identify = true
                                end
                                pos = msg_start + msg_len
                            elseif found_identify then
                                -- This is the length-prefixed protobuf Identify message
                                pinfo.cols.protocol:set("LIBP2P-ID")
                                pinfo.cols.info:set("Identify")
                                local id_tree = subtree:add(proto_identify, data_tvb(pos, consumed + msg_len), "Identify Message")
                                dissect_identify_pb(data_tvb, msg_start, msg_len, id_tree)
                                pos = msg_start + msg_len
                            else
                                break
                            end
                        end

                        if not found_identify or pos <= 20 + 15 then
                            -- Only negotiation, no payload
                            pinfo.cols.protocol:set("LIBP2P-ID")
                            pinfo.cols.info:set("Identify (negotiation)")
                        end
                    end
                end
            end
        end
    end
end

register_postdissector(proto_identify)
