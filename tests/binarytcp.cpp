#include "vscp-binary-protocol.h"
#include "controlobject.h"

#include <cassert>
#include <iostream>

static std::vector<uint8_t>
command(uint16_t code, uint8_t encryption, const uint8_t* key,
        const std::vector<uint8_t>& arguments = {})
{
    std::vector<uint8_t> frame(arguments.size() + 5, 0), wire;
    assert(vscp_writeCommandToFrame(frame.data(), frame.size(), code,
                                    arguments.empty() ? nullptr : arguments.data(),
                                    arguments.size()) == VSCP_ERROR_SUCCESS);
    vscp_binary::setCrc(frame);
    assert(vscp_binary::encode(frame, encryption, key, wire));
    return wire;
}

static void feed(CTcpipSrv& server, mg_connection* connection,
                 const uint8_t* data, size_t length)
{
    assert(mg_iobuf_add(&connection->recv, connection->recv.len,
                        data, length) == length);
    server.handleIncomingData(connection);
}

static std::vector<uint8_t> receive(mg_connection* connection, const uint8_t* key)
{
    assert(connection->send.len >= vscp_binary::headerSize + 1);
    size_t length = 0;
    assert(vscp_binary::parseHeader(connection->send.buf, length));
    assert(connection->send.len >= length + vscp_binary::headerSize);
    std::vector<uint8_t> frame;
    assert(vscp_binary::decode(
      std::vector<uint8_t>(connection->send.buf + vscp_binary::headerSize,
                           connection->send.buf + vscp_binary::headerSize + length),
      key, frame));
    mg_iobuf_del(&connection->send, 0, length + vscp_binary::headerSize);
    return frame;
}

void testBinaryTcp()
{
    CControlObject control;
    CTcpipSrv& server = control.getTcpipSrv();
    const uint8_t* key = control.getSystemKey(nullptr);
    mg_mgr manager;
    mg_mgr_init(&manager);
    mg_connection* connection = mg_alloc_conn(&manager);
    assert(connection != nullptr);
    CClientItem client;
    client.setControlObject(&control);
    client.setConnection(connection);
    client.setConnected(true);
    connection->fn_data = &client;
    const uint8_t binary[] = {'B', 'I', 'N', 'A', 'R', 'Y', '\r', '\n'};
    feed(server, connection, binary, sizeof(binary));
    assert(client.isBinaryMode());
    assert(std::string(reinterpret_cast<char*>(connection->send.buf),
                        connection->send.len) == MSG_OK);
    mg_iobuf_del(&connection->send, 0, connection->send.len);
    for (uint8_t encryption = 0; encryption <= 3; ++encryption) {
        auto request = command(0, encryption, key);
        for (size_t i = 0; i < request.size(); ++i) {
            feed(server, connection, request.data() + i, 1);
            if (i + 1 < request.size()) assert(connection->send.len == 0);
        }
        auto reply = receive(connection, key);
        assert(reply.size() == 7 && reply[0] == (0xf0 | encryption));
        assert(vscp_binary::read16(reply.data() + 1) == 0);
        assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_SUCCESS);
    }
    auto version = command(16, 3, key);
    auto denied = command(7, 3, key);
    version.insert(version.end(), denied.begin(), denied.end());
    feed(server, connection, version.data(), version.size());
    auto reply = receive(connection, key);
    assert(reply.size() == 17 && vscp_binary::read16(reply.data() + 1) == 16);
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_NOT_AUTHORIZED);
    assert(!client.isReceiveLoopActive());

    assert(control.getUserList().addUser("binary-test", "", "", "", nullptr,
                                         "admin", "*", "*:*"));
    client.setUserItem(control.getUserList().getUser("binary-test"));
    client.setAuthenticated(true);
    client.setClientID(42);
    for (auto entry : {std::pair<uint16_t, size_t>{9, 11}, {10, 7},
                       {11, 39}, {12, 20}, {13, 11}, {15, 23},
                       {16, 17}, {21, 15}}) {
        auto request = command(entry.first, 3, key);
        feed(server, connection, request.data(), request.size());
        reply = receive(connection, key);
        assert(reply.size() == entry.second);
        assert(vscp_binary::read16(reply.data() + 1) == entry.first);
        assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_SUCCESS);
    }
    for (uint16_t code : {14, 17, 18, 19}) {
        auto request = command(code, 3, key);
        feed(server, connection, request.data(), request.size());
        reply = receive(connection, key);
        assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_PARAMETER);
    }
    auto open = command(7, 3, key);
    feed(server, connection, open.data(), open.size());
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_SUCCESS);
    assert(client.isReceiveLoopActive());
    vscpEvent* event = nullptr;
    assert(vscp_newEvent(&event));
    event->head = VSCP_HEADER16_FRAME_VERSION_UNIX_NS;
    event->timestamp_ns = 123456789;
    event->vscp_class = 20;
    event->vscp_type = 3;
    assert(client.addEventToSendQueue(event));
    assert(server.sendOneEventFromQueue(connection, false));
    reply = receive(connection, key);
    assert(reply[0] == 0x13 && reply.size() == 38);

    auto close = command(8, 3, key);
    feed(server, connection, close.data(), close.size());
    receive(connection, key);
    assert(!client.isReceiveLoopActive());
    std::vector<uint8_t> incoming = reply;
    incoming[0] = 0x10;
    std::vector<uint8_t> wire;
    assert(vscp_binary::encode(incoming, 2, key, wire));
    feed(server, connection, wire.data(), wire.size());
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 0xffff);
    assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_SUCCESS);
    event = control.getClientList().getEventFromClientMainReceiveQueue(true);
    assert(event && event->obid == 42 && event->vscp_class == 20);
    vscp_deleteEvent_v2(&event);

    assert(vscp_newEvent(&event));
    event->head = VSCP_HEADER16_FRAME_VERSION_UNIX_NS;
    assert(client.addEventToSendQueue(event));
    auto retr = command(6, 2, key);
    feed(server, connection, retr.data(), retr.size());
    reply = receive(connection, key);
    assert(reply.size() == 42 && vscp_binary::read16(reply.data() + 1) == 6);
    assert(client.getClientSendQueueSize() == 0);
    auto text = command(24, 2, key);
    text.insert(text.end(), {'N', 'O', 'O', 'P', '\r', '\n'});
    feed(server, connection, text.data(), text.size());
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 24);
    assert(!client.isBinaryMode() && client.isAuthenticated());
    assert(std::string(reinterpret_cast<char*>(connection->send.buf),
                        connection->send.len) == MSG_OK);
    assert(!connection->is_closing);
    mg_iobuf_del(&connection->send, 0, connection->send.len);
    std::vector<uint8_t> transition(binary, binary + sizeof(binary));
    auto noop = command(0, 1, key);
    transition.insert(transition.end(), noop.begin(), noop.end());
    feed(server, connection, transition.data(), transition.size());
    assert(client.isBinaryMode() && client.isAuthenticated());
    assert(std::string(reinterpret_cast<char*>(connection->send.buf),
                        sizeof(MSG_OK) - 1) == MSG_OK);
    mg_iobuf_del(&connection->send, 0, sizeof(MSG_OK) - 1);
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 0);

    // Garbage, a bad header and a corrupt CRC are skipped; the connection
    // stays open and the next valid frame is handled.
    std::vector<uint8_t> noisy = {'x', 0x55, 0xff, 0xff, 0x00, 0x55};
    auto corrupt = command(0, 0, key);
    corrupt.back() ^= 0xff;
    noisy.insert(noisy.end(), corrupt.begin(), corrupt.end());
    auto version16 = command(16, 0, key);
    noisy.insert(noisy.end(), version16.begin(), version16.end());
    feed(server, connection, noisy.data(), noisy.size());
    assert(!connection->is_closing && !client.isBinaryResyncing());
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 0xffff);
    assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_INVALID_FRAME);
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 16);
    assert(connection->send.len == 0);

    // A false header claiming a long frame stalls only until the timeout.
    const uint8_t stall[] = {0x55, 0x2f, 0xff, 0xe0};
    feed(server, connection, stall, sizeof(stall));
    auto afterStall = command(0, 1, key);
    feed(server, connection, afterStall.data(), afterStall.size());
    assert(connection->send.len == 0 && client.getBinaryPartialSince());
    uint64_t since = client.getBinaryPartialSince();
    server.checkBinaryReceiveTimeout(connection, since + 1);
    assert(connection->send.len == 0);
    server.checkBinaryReceiveTimeout(
      connection, since + vscp_binary::partialFrameTimeoutMs);
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 3) == VSCP_ERROR_INVALID_FRAME);
    reply = receive(connection, key);
    assert(vscp_binary::read16(reply.data() + 1) == 0);
    assert(reply[0] == 0xf1 && !connection->is_closing);
    assert(connection->recv.len == 0 && !client.getBinaryPartialSince());
    mg_mgr_free(&manager);
    std::cout << "Binary TCP: fragmented AES commands, coalesced frames, "
                 "authorization, asynchronous events, RETR, TEXT and resync passed\n";
}
