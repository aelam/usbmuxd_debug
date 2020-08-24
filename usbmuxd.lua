usbmux_protocol = Proto("usbmux", "Apple USBMUX Protocol")
plist_protocol = Proto("plist", "Plist payload")


local usbmuxd_msgtypes = {"result", "connect", "listen", "device_add", "remove", "paired", "unknown", "plist"}

-- enum usbmuxd_msgtype {
	local MESSAGE_RESULT  = 1
	local MESSAGE_CONNECT = 2
	local MESSAGE_LISTEN = 3
	local MESSAGE_DEVICE_ADD = 4
	local MESSAGE_DEVICE_REMOVE = 5
	local MESSAGE_DEVICE_PAIRED = 6
	local MESSAGE_PLIST = 8
-- };




local header_fields =
{
    message_length = ProtoField.int32("usbmux.message_length", "message_length", base.DEC),
    version = ProtoField.int32("usbmux.version", "version", base.DEC),
    message_type = ProtoField.int32("usbmux.message_type", "message_type", base.DEC),
    tag = ProtoField.int32("usbmux.tag", "tag", base.DEC),
    payload = ProtoField.string("usbmux.payload", "payload"),
}

message_plist = Proto("usbmux.message", "Plist protocol");


usbmux_protocol.fields = header_fields

function usbmux_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = usbmux_protocol.name

    local subtree = tree:add(usbmux_protocol, buffer(), "USBMUX Protocol Data")

    local offset = 0
    local msg_length = buffer(0,4):le_uint()
    subtree:add_le(header_fields.message_length, buffer(offset, 4))
    offset = offset + 4
    subtree:add_le(header_fields.version, buffer(offset, 4))
    offset = offset + 4
    local msg_type = buffer(offset, 4):le_uint()
    local msg_type_name = usbmuxd_msgtypes[msg_type]
    subtree:add_le(header_fields.message_type, buffer(offset, 4))
    
    offset = offset + 4
    subtree:add_le(header_fields.tag, buffer(offset, 4))
    offset = offset + 4

    if (msg_type == MESSAGE_PLIST) then
        -- message_plist.fields = {plist_field}
        -- local extendtree = subtree:add(message_plist, buffer(offset, msg_length-offset):tvb(),"message")
        -- extendtree:add(header_fields.payload, buffer(offset, msg_length-offset))
        -- https://stackoverflow.com/questions/46149825/wireshark-display-filters-vs-nested-dissectors
        local xml_dissector = Dissector.get("xml")
        xml_dissector(buffer(offset, msg_length-offset):tvb(), pinfo, subtree)
        -- xml_dissector.dissector(buffer(offset, msg_length-offset):tvb(), pinfo, subtree)
    end

end

function plist_protocol.dissector(tvb, pinfo, tree)
    local xml_dissector = Dissector.get("xml")
    pinfo.cols.protocol = "plist"
    xml_dissector(tvb, pinfo, tree)
end


local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9876, usbmux_protocol)
-- register_postdissector(plist_protocol)
