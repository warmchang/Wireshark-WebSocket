--  _       __     __   _____            __        __     _____
-- | |     / /__  / /_ / ___/____  _____/ /_____  / /_   /__  /
-- | | /| / / _ \/ __ \\__ \/ __ \/ ___/ //_/ _ \/ __/_____/ /
-- | |/ |/ /  __/ /_/ /__/ / /_/ / /__/ ,< /  __/ /_/_____/ /__
-- |__/|__/\___/_.___/____/\____/\___/_/|_|\___/\__/     /____/

--[[ WebSocket-Z,  decode the masked payload,  v0.3,  warmchang@outlook.com,  2016-03-08 ]]
--[[ WebSocket-Z,  add the opcode,  v0.2,  warmchang@outlook.com,  2016-03-03 ]]
--[[ WebSocket-Z,  dissector fo websocket,  v0.1,  warmchang@outlook.com,  2015-12-24 ]]

--  0                   1                   2                   3
--  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- +-+-+-+-+-------+-+-------------+-------------------------------+
-- |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
-- |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
-- |N|V|V|V|       |S|             |   (if payload len==126/127)   |
-- | |1|2|3|       |K|             |                               |
-- +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
-- |     Extended payload length continued, if payload len == 127  |
-- + - - - - - - - - - - - - - - - +-------------------------------+
-- |                               |Masking-key, if MASK set to 1  |
-- +-------------------------------+-------------------------------+
-- | Masking-key (continued)       |          Payload Data         |
-- +-------------------------------- - - - - - - - - - - - - - - - +
-- :                     Payload Data continued ...                :
-- + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
-- |                     Payload Data continued ...                |
-- +---------------------------------------------------------------+

do
    local p_websocket = Proto("WebSocket-Z", "WebSocket-Z")
    local thebool = { [0] = "False", [1] = "True" }
    local themask = { [0] = " ", [1] = " [MASKED]" }

    -- description table for Opcode
    local theopcode = {
        [0] = "continues",
        [1] = "WebSocket Text [FIN]",
        [2] = "WebSocket binary [FIN]",
        [3] = "reserved for further non-control frames",
        [4] = "reserved for further non-control frames",
        [5] = "reserved for further non-control frames",
        [6] = "reserved for further non-control frames",
        [7] = "reserved for further non-control frames",
        [8] = "WebSocket Connection Close [FIN]",
        [9] = "WebSocket Ping [FIN]",
        [10] = "WebSocket Pong [FIN]",
        [11] = "reserved for further control frames",
        [12] = "reserved for further control frames",
        [13] = "reserved for further control frames",
        [14] = "reserved for further control frames",
        [15] = "reserved for further control frames",
    }

    local f_fin = ProtoField.uint8("WebSocket-Z.fin", "Fin", nil, thebool, 0x80)
    local f_reserved = ProtoField.uint8("WebSocket-Z.reserved", "Reserved", base.HEX, nil, 0x70)
    local f_opcode = ProtoField.uint8("WebSocket-Z.opcode", "Opcode", nil, theopcode, 0x0F)
    local f_mask = ProtoField.uint8("WebSocket-Z.mask", "Mask", nil, thebool, 0x80)
    local f_payloadlen = ProtoField.uint8("WebSocket-Z.payloadlen", "Payload length", base.DEC, nil, 0x7F)
    local f_extpayloadlen = ProtoField.uint16("WebSocket-Z.extpayloadlen", "Extended Payload length (16 bits)", base.DEC)
    local f_maskingkey = ProtoField.uint32("WebSocket-Z.maskingkey", "Masking-key", base.HEX)
    local f_payload = ProtoField.string("WebSocket-Z.Payload", "Payload")

    p_websocket.fields = { f_fin, f_reserved, f_opcode, f_mask, f_payloadlen, f_extpayloadlen, f_maskingkey, f_payload }


    -- GetBits: Get some consecutive bits value from a WORD
    -- Param description:
    --     src: the source value from which we want to extract bit value
    --     sb:  startbit, the leftmost bit is refferred to as 0, the rightmost 15
    --     eb:  endbit, same as sb
    -- return value: the extracted bits value.
    local function GetBits(src, sb, eb)
        if src > 65535 or sb > 15 or eb > 15 or sb > eb then return 0 end
        local temp = src % (2 ^ (16 - sb))
        local tail = temp % (2 ^ (15 - eb))
        temp = temp - tail
        temp = temp / (2 ^ (15 - eb))
        return temp
    end


    -- decode the data string
    local bxor = bit.bxor
    local byte = string.byte
    local concat = table.concat
    local transformed = {}
    local function XORMask(data, mask)
        for i = 1, #data do
            transformed[i] = bxor(data[i], mask[(i - 1) % 4 + 1])
        end

        return transformed
    end


    --将16进制串转换为字符串
    function hex2str(hex)
        --判断输入类型
        if (type(hex) ~= "string") then
            return nil, "hex2str invalid input type"
        end
        --拼接字符串
        local index = 1
        local ret = ""
        for index = 1, hex:len() do
            ret = ret .. string.format("%02X", hex:sub(index):byte())
        end

        return ret
    end


    --将字符串按格式转为16进制串
    function str2hex(str)
        --判断输入类型
        if (type(str) ~= "string") then
            return nil, "str2hex invalid input type"
        end
        --滤掉分隔符
        str = str:gsub("[%s%p]", ""):upper()
        --检查内容是否合法
        if (str:find("[^0-9A-Fa-f]") ~= nil) then
            return nil, "str2hex invalid input content"
        end
        --检查字符串长度
        if (str:len() % 2 ~= 0) then
            return nil, "str2hex invalid input lenth"
        end
        --拼接字符串
        local index = 1
        local ret = ""
        for index = 1, str:len(), 2 do
            ret = ret .. string.char(tonumber(str:sub(index, index + 1), 16))
        end

        return ret
    end


    -- the websocket dissector function
    local function p_websocket_dissector(buffer, pkt, root)
        local buf_len = buffer:len()
        if buf_len < 2 then return false end

        local subtree = root:add(p_websocket, buffer())
        subtree:append_text(", websocket_len = " .. buf_len)

        local offset = 0
        local tag = buffer(offset, 1)

        subtree:add(f_fin, tag)

        local bo = GetBits(tag:uint(), 0, 0)

        if (bo ~= 1 and bo ~= 0) then
            subtree:append_text(", error:unknown byteorder:" .. bo)
            return false
        end

        subtree:add(f_reserved, tag)
        subtree:add(f_opcode, tag)

        local tag2 = buffer(offset, 2)
        local opcode = 0
        opcode = GetBits(tag2:uint(), 1, 7)
        -- pkt.cols.info = string.format("%-22s", theopcode[opcode])

        offset = offset + 1
        tag = buffer(offset, 1)

        local payloadlen = 0
        local mask = 0
        if buf_len > 2 then
            tag2 = buffer(offset, 2)
            payloadlen = GetBits(tag2:uint(), 1, 7)
            mask = GetBits(tag2:uint(), 0, 0)
        end

        pkt.cols.protocol = "WebSocket-Z"
        if (opcode > 15) then
            pkt.cols.info = "-->it's not a websocket package<--"
        elseif (mask == 1 or mask == 0) then
            pkt.cols.info = string.format("%-22s", theopcode[opcode] .. themask[mask])
        else
            pkt.cols.info = string.format("%-22s", theopcode[opcode])
            -- return false
        end

        subtree:add(f_mask, tag)
        subtree:add(f_payloadlen, tag)

        offset = offset + 1

        local realpayloadlen = 0
        if (payloadlen == 126) then
            tag = buffer(offset, 2)
            subtree:add(f_extpayloadlen, tag)
            realpayloadlen = buffer(offset, 2):uint()
            offset = offset + 2
        else
            realpayloadlen = payloadlen
        end
        subtree:append_text(", realpayloadlen:" .. realpayloadlen)

        local maskstr
        local masktable = {}
        if (mask == 1) then
            tag = buffer(offset, 4)
            subtree:add(f_maskingkey, tag)
            local maskstr = buffer(offset, 4):bytes()
            for i = 1, 4 do
                masktable[i] = maskstr:get_index(i - 1)
            end
            -- subtree:append_text(", masktable:"..masktable[1]..masktable[2]..masktable[3]..masktable[4])
            offset = offset + 4
        end

        local maskedtable = {}
        local decodepayloadstr = {}
        if (realpayloadlen > 0) then
            local payload = buffer(offset)
            if (mask == 1) then
                local maskedstr = buffer(offset):bytes()
                for i = 1, realpayloadlen do
                    maskedtable[i] = maskedstr:get_index(i - 1)
                end
                -- subtree:append_text(", maskedtable:"..maskedtable[1]..maskedtable[2]..maskedtable[3]..maskedtable[4])

                -- subtree:append_text(", payloadstr0:"..payloadstr0)
                -- subtree:append_text(", mask:"..maskstr)
                -- local payloadstr = tostring(payload)
                -- subtree:append_text(", payload:"..payloadstr)
                -- local payloadstr0 = table.concat(maskedtable);
                -- subtree:append_text(", payloadstr0:"..payloadstr0)

                decodepayloadstr = XORMask(maskedtable, masktable)
                local hehe = ""
                -- for i = 1,#decodepayloadstr do
                for i = 1, realpayloadlen do
                    hehe = hehe .. string.char(decodepayloadstr[i])
                end
                -- subtree:append_text(", decodepayloadstr:"..hehe)
                -- subtree:append_text(", decodepayloadstr:"..table.concat(hehe))
                subtree:add(f_payload, hehe)
            else
                subtree:add(f_payload, payload)
                -- local payloadstr0 = buffer(offset):string()
                -- subtree:append_text(", payloadstr0:"..payloadstr0)
            end
        end

        return true
    end


    function p_websocket.dissector(buf, pkt, root)
        if p_websocket_dissector(buf, pkt, root) then
        else
            -- if not my procotol, call data
            -- get the packet's data field
            local data_dis = Dissector.get("data")
            data_dis:call(buf, pkt, root)
        end
    end


    -- register to tcp.port = 8888
    local websocket_disc_table = DissectorTable.get("tcp.port")
    websocket_disc_table:add(8888, p_websocket)
end
