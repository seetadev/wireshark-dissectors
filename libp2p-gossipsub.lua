-- Wireshark Lua dissector for libp2p GossipSub (/meshsub/1.x.0, /floodsub/1.0.0)
-- Uses stream reassembly from libp2p-common.lua.

if not libp2p or not libp2p._loaded then
    local script_dir = debug.getinfo(1, "S").source:match("@?(.*/)") or ""
    dofile(script_dir .. "libp2p-common.lua")
    libp2p._loaded = true
end

local proto_gs = Proto("libp2p_gossipsub", "libp2p GossipSub")

proto_gs.fields = {}

local gossipsub_protocols = {}
for _, p in ipairs({
    "/meshsub/1.0.0", "/meshsub/1.1.0", "/meshsub/1.2.0", "/meshsub/1.3.0",
    "/floodsub/1.0.0",
}) do gossipsub_protocols[p] = true end

local function dissect_subopts(s, from, to, tree)
    local subtree = tree:add("Subscription")
    local subscribe_val, topic_val = nil, nil
    libp2p.pb_each_str(s, from, to, function(fnum, wtype, dstart, dlen, val)
        if fnum == 1 and wtype == 0 then
            subscribe_val = (val ~= 0)
            subtree:add("Subscribe: " .. tostring(subscribe_val))
        elseif fnum == 2 and wtype == 2 then
            topic_val = s:sub(dstart, dstart + dlen - 1)
            subtree:add("Topic ID: " .. topic_val)
        end
    end)
    local action = subscribe_val and "SUBSCRIBE" or "UNSUBSCRIBE"
    subtree:set_text(string.format("Subscription: %s %s", action, topic_val or ""))
    return action, topic_val
end

local function dissect_message(s, from, to, tree)
    local subtree = tree:add("Message")
    local topic_val = nil
    local data_len = nil
    libp2p.pb_each_str(s, from, to, function(fnum, wtype, dstart, dlen, val)
        if wtype ~= 2 then return end
        local raw = s:sub(dstart, dstart + dlen - 1)
        if fnum == 1 then
            subtree:add("From: " .. libp2p.bytes_to_hex(raw))
        elseif fnum == 2 then
            data_len = dlen
            subtree:add("Data Length: " .. dlen .. " bytes")
            subtree:add("Data: " .. libp2p.bytes_to_hex(raw))
            if raw:match("^[%g%s]+$") then
                subtree:add("Data (string): " .. raw)
            end
        elseif fnum == 3 then
            subtree:add("Sequence Number: " .. libp2p.bytes_to_hex(raw))
        elseif fnum == 4 then
            topic_val = raw
            subtree:add("Topic: " .. raw)
        elseif fnum == 5 then
            subtree:add("Signature: " .. libp2p.bytes_to_hex(raw))
        elseif fnum == 6 then
            subtree:add("Key: " .. libp2p.bytes_to_hex(raw))
        end
    end)
    local label = string.format("Message [%s]", topic_val or "?")
    if data_len then label = label .. string.format(" (%d bytes)", data_len) end
    subtree:set_text(label)
    return topic_val
end

local function dissect_control(s, from, to, tree)
    local subtree = tree:add("Control")
    local parts = {}
    libp2p.pb_each_str(s, from, to, function(fnum, wtype, dstart, dlen, val)
        if wtype ~= 2 then return end
        local inner_from, inner_to = dstart, dstart + dlen - 1
        if fnum == 1 then
            local ih_tree = subtree:add("IHAVE")
            local topic = nil
            libp2p.pb_each_str(s, inner_from, inner_to, function(fn2, wt2, ds2, dl2, v2)
                if wt2 ~= 2 then return end
                if fn2 == 1 then topic = s:sub(ds2, ds2+dl2-1); ih_tree:add("Topic: " .. topic)
                elseif fn2 == 2 then ih_tree:add("Message ID: " .. libp2p.bytes_to_hex(s:sub(ds2, ds2+dl2-1)))
                end
            end)
            table.insert(parts, string.format("IHAVE(%s)", topic or ""))
        elseif fnum == 2 then
            local iw_tree = subtree:add("IWANT")
            libp2p.pb_each_str(s, inner_from, inner_to, function(fn2, wt2, ds2, dl2, v2)
                if fn2 == 1 and wt2 == 2 then iw_tree:add("Message ID: " .. libp2p.bytes_to_hex(s:sub(ds2, ds2+dl2-1))) end
            end)
            table.insert(parts, "IWANT")
        elseif fnum == 3 then
            local g_tree = subtree:add("GRAFT")
            local topic = nil
            libp2p.pb_each_str(s, inner_from, inner_to, function(fn2, wt2, ds2, dl2, v2)
                if fn2 == 1 and wt2 == 2 then topic = s:sub(ds2, ds2+dl2-1); g_tree:add("Topic: " .. topic) end
            end)
            table.insert(parts, string.format("GRAFT(%s)", topic or ""))
        elseif fnum == 4 then
            local p_tree = subtree:add("PRUNE")
            local topic = nil
            libp2p.pb_each_str(s, inner_from, inner_to, function(fn2, wt2, ds2, dl2, v2)
                if fn2 == 1 and wt2 == 2 then topic = s:sub(ds2, ds2+dl2-1); p_tree:add("Topic: " .. topic)
                elseif fn2 == 3 and wt2 == 0 then p_tree:add("Backoff: " .. tostring(v2))
                end
            end)
            table.insert(parts, string.format("PRUNE(%s)", topic or ""))
        elseif fnum == 5 then
            local idw_tree = subtree:add("IDONTWANT")
            libp2p.pb_each_str(s, inner_from, inner_to, function(fn2, wt2, ds2, dl2, v2)
                if fn2 == 1 and wt2 == 2 then idw_tree:add("Message ID: " .. libp2p.bytes_to_hex(s:sub(ds2, ds2+dl2-1))) end
            end)
            table.insert(parts, "IDONTWANT")
        end
    end)
    subtree:set_text("Control: " .. table.concat(parts, ", "))
    return parts
end

local function dissect_rpc(s, from, to, tree)
    local rpc_tree = tree:add("RPC")
    local summary_parts = {}
    libp2p.pb_each_str(s, from, to, function(fnum, wtype, dstart, dlen, val)
        if wtype ~= 2 then return end
        local inner_to = dstart + dlen - 1
        if fnum == 1 then
            local action, topic = dissect_subopts(s, dstart, inner_to, rpc_tree)
            table.insert(summary_parts, string.format("%s(%s)", action or "SUB", topic or "?"))
        elseif fnum == 2 then
            local topic = dissect_message(s, dstart, inner_to, rpc_tree)
            table.insert(summary_parts, string.format("PUBLISH(%s)", topic or "?"))
        elseif fnum == 3 then
            local ctrl_parts = dissect_control(s, dstart, inner_to, rpc_tree)
            for _, p in ipairs(ctrl_parts) do table.insert(summary_parts, p) end
        end
    end)
    local summary = table.concat(summary_parts, ", ")
    rpc_tree:set_text("RPC: " .. summary)
    return summary
end

function proto_gs.dissector(tvb, pinfo, tree)
    local streams = libp2p.process_streams(pinfo)
    for _, st in ipairs(streams) do
        if not gossipsub_protocols[st.protocol] then goto next end

        if not st.payload or #st.payload == 0 then
            local subtree = tree:add(proto_gs, tvb(), "libp2p GossipSub [" .. st.protocol .. "]")
            pinfo.cols.protocol:set("GOSSIPSUB")
            pinfo.cols.info:set("GossipSub (negotiation)")
            goto next
        end

        local payload = st.payload
        local prev = st.prev_payload_len
        local pos = 1
        local last_summary = nil

        while pos <= #payload do
            local rpc_len, consumed = libp2p.decode_varint_str(payload, pos)
            if consumed == 0 or rpc_len == 0 or pos + consumed + rpc_len - 1 > #payload then
                break
            end
            local rpc_start = pos + consumed
            local rpc_end = rpc_start + rpc_len - 1

            if rpc_end > prev then
                local subtree = tree:add(proto_gs, tvb(), "libp2p GossipSub [" .. st.protocol .. "]")
                last_summary = dissect_rpc(payload, rpc_start, rpc_end, subtree)
            end

            pos = rpc_end + 1
        end

        if last_summary then
            pinfo.cols.protocol:set("GOSSIPSUB")
            pinfo.cols.info:set("GossipSub " .. last_summary)
        end

        ::next::
    end
end

register_postdissector(proto_gs)
