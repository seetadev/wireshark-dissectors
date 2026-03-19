-- Wireshark Lua dissector for libp2p Identify protocol (/ipfs/id/1.0.0)
-- Uses stream reassembly from libp2p-common.lua.

if not libp2p or not libp2p._loaded then
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    dofile(script_dir .. "libp2p-common.lua")
    libp2p._loaded = true
end

local proto_id = Proto("libp2p_identify", "libp2p Identify")

proto_id.fields = {}

local identify_protocols = {
    ["/ipfs/id/1.0.0"] = true,
    ["/ipfs/id/push/1.0.0"] = true,
}

local function dissect_identify_pb(s, from, to, tree)
    libp2p.pb_each_str(s, from, to, function(fnum, wtype, dstart, dlen, val)
        if wtype ~= 2 then return end
        local raw = s:sub(dstart, dstart + dlen - 1)
        if fnum == 1 then
            tree:add("Public Key: " .. libp2p.bytes_to_hex(raw))
        elseif fnum == 2 then
            tree:add("Listen Address: " .. libp2p.format_multiaddr(raw))
        elseif fnum == 3 then
            tree:add("Protocol: " .. raw)
        elseif fnum == 4 then
            tree:add("Observed Address: " .. libp2p.format_multiaddr(raw))
        elseif fnum == 5 then
            tree:add("Protocol Version: " .. raw)
        elseif fnum == 6 then
            tree:add("Agent Version: " .. raw)
        elseif fnum == 8 then
            tree:add("Signed Peer Record: " .. libp2p.bytes_to_hex(raw))
        end
    end)
end

function proto_id.dissector(tvb, pinfo, tree)
    local streams = libp2p.process_streams(pinfo)
    for _, s in ipairs(streams) do
        if not identify_protocols[s.protocol] then goto next end

        if not s.payload or #s.payload == 0 then
            local subtree = tree:add(proto_id, tvb(), "libp2p Identify [" .. s.protocol .. "]")
            pinfo.cols.protocol:set("LIBP2P-ID")
            pinfo.cols.info:set("Identify (negotiation)")
            goto next
        end

        local payload = s.payload
        local pos = 1
        while pos <= #payload do
            local pb_len, consumed = libp2p.decode_varint_str(payload, pos)
            if consumed == 0 or pb_len == 0 or pos + consumed + pb_len - 1 > #payload then
                break
            end
            local pb_start = pos + consumed
            local pb_end = pb_start + pb_len - 1

            local subtree = tree:add(proto_id, tvb(), "libp2p Identify [" .. s.protocol .. "]")
            local id_tree = subtree:add("Identify Message")
            dissect_identify_pb(payload, pb_start, pb_end, id_tree)

            pinfo.cols.protocol:set("LIBP2P-ID")
            pinfo.cols.info:set("Identify")

            pos = pb_end + 1
        end

        ::next::
    end
end

register_postdissector(proto_id)
