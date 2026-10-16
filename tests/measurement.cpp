#include "controlobject.h"
#include "measurement-command.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <iostream>
#include <limits>

namespace {

const std::array<uint8_t, 16> interfaceGuid =
  {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

vscpEventEx parse(const std::string& arguments)
{
    vscpEventEx event{};
    if (!parseMeasurementCommand(arguments, interfaceGuid.data(), event)) {
        std::cerr << "Unexpectedly rejected: " << arguments << '\n';
        assert(false);
    }
    assert((event.head & VSCP_HEADER16_FRAME_VERSION_MASK) ==
           VSCP_HEADER16_FRAME_VERSION_UNIX_NS);
    assert(event.year == 0xffff && event.month == 0xff);
    return event;
}

void payload(const vscpEventEx& event, std::initializer_list<uint8_t> expected)
{
    assert(event.sizeData == expected.size());
    assert(std::equal(expected.begin(), expected.end(), event.data));
}

void testEncodings()
{
    for (unsigned cls = 10; cls <= 14; ++cls) {
        auto event = parse(std::to_string(cls) + ",6,-129,3,7");
        assert(event.vscp_class == cls && event.vscp_type == 6);
        payload(event, {0x7f, 0xff, 0x7f});
        payload(parse(std::to_string(cls) + ",6,1.5,1,2"),
                {0xaa, 0x3f, 0xc0, 0, 0});
    }
    for (unsigned cls = 60; cls <= 64; ++cls) {
        auto event = parse(std::to_string(cls) + ",6,1.5");
        assert(event.vscp_class == cls);
        payload(event, {0x3f, 0xf8, 0, 0, 0, 0, 0, 0});
    }
    for (unsigned cls : {65, 66, 67, 68, 69, 85, 86, 87, 88, 89}) {
        auto event = parse(std::to_string(cls) + ",6,-23.5,1,255,2,3");
        assert(event.vscp_class == cls);
        payload(event, {255, 2, 3, 0x88, 0x81, 0xff, 0x15});
    }
    for (unsigned cls = 70; cls <= 74; ++cls) {
        auto event = parse(std::to_string(cls) + ",6,1.5");
        assert(event.vscp_class == cls);
        payload(event, {0x3f, 0xc0, 0, 0});
    }
    payload(parse("1060,65535,-1.5,255,254,253,252"),
            {254, 253, 252, 255, 0xbf, 0xf8, 0, 0, 0, 0, 0, 0});
    auto event = parse("1040,1280,+001.2300,255,254,253,252");
    payload(event, {254, 253, 252, 255, '+', '0', '0', '1', '.', '2', '3', '0', '0', 0});
    payload(parse("0X0A,0x06,+127,0x03,0X07"), {0x7f, 127});
    payload(parse("10,6,128"), {0x60, 0, 0x80});
    payload(parse("10,6,-128"), {0x60, 0x80});
    payload(parse("10,6,36028797018963967"), {0x60, 0x7f, 255, 255, 255, 255, 255, 255});
    payload(parse("10,6,-36028797018963968"), {0x60, 0x80, 0, 0, 0, 0, 0, 0});
    payload(parse("65,6,8388607"), {0, 0, 0, 0x80, 0, 0x7f, 255, 255});
    payload(parse("65,6,-8388608"), {0, 0, 0, 0x80, 0, 0x80, 0, 0});
    payload(parse("65,6,1e-127"), {0, 0, 0, 0x80, 0xff, 1});
    payload(parse("65,6,1e128"), {0, 0, 0, 0x80, 127, 10});
    payload(parse("65,6,1000e127"), {0, 0, 0, 0x80, 127, 3, 0xe8});
    payload(parse("65,6,0e999"), {0, 0, 0, 0x80, 0, 0});
    assert(parse("1040,6," + std::string(483, '9')).sizeData == 488);
    assert(parse("60,6,1.7976931348623157e308").sizeData == 8);
    assert(parse("70,6,3.4028234663852886e38").sizeData == 4);
}

void testDefaultsAndTimestamps()
{
    uint64_t before = vscp_makeTimeStampNs();
    auto event = parse(" 1060 , 6 , 1.5 , , , , , , ");
    uint64_t after = vscp_makeTimeStampNs();
    assert(event.timestamp_ns >= before && event.timestamp_ns <= after);
    assert(std::equal(interfaceGuid.begin(), interfaceGuid.end(), event.GUID));
    payload(event, {0, 0, 0, 0, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0});
    assert(parse("10,6,1,,,,,,0").timestamp_ns == 0);
    assert(parse("10,6,1,,,,,-,18446744073709551615").timestamp_ns ==
           std::numeric_limits<uint64_t>::max());
    assert(parse("10,6,1,,,,,,@1970-01-01T00:00:00Z").timestamp_ns == 0);
    assert(parse("10,6,1,,,,,,@1970-01-01T00:00:00.000000001Z").timestamp_ns == 1);
    assert(parse("10,6,1,,,,,,@1970-01-01T00:00:01.1+00:00").timestamp_ns == 1100000000);
    assert(parse("10,6,1,,,,,,@2000-02-29T00:00:00").timestamp_ns == 951782400000000000ULL);
    assert(parse("10,6,1,,,,,,@2024-02-29T00:00:00.123456789Z").timestamp_ns ==
           1709164800123456789ULL);
    event = parse("10,6,1,,,,,FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00,42");
    assert(event.timestamp_ns == 42 && event.GUID[0] == 255 && event.GUID[15] == 0);
}

void testInvalidInput()
{
    for (const auto& arguments : {
           "", "10", "10,6", ",6,1", "10,,1", "10,6,", "15,6,1",
           "59,6,1", "75,6,1", "90,6,1", "65536,6,1", "10,256,1",
           "1060,65536,1", "10,6,nan", "10,6,inf", "10,6,1junk",
           "10,6,1.2.3", "10,6,1e", "10,6,+", "10,6,.", "10,6,1e10001",
           "10,6,1,4", "10,6,1,0,8", "10,6,1,0,0,1",
           "10,6,1,0,0,0,1", "65,6,1,4", "65,6,1,0,256",
           "1060,6,1,256", "1060,6,1,0,0,-1", "1060,6,1,0,0,0,256",
           "60,6,1,1", "70,6,1,0,1", "60,6,1,0,0,1", "70,6,1,0,0,0,1",
           "10,6,36028797018963968", "10,6,-36028797018963969",
           "65,6,8388609", "65,6,-8388609", "65,6,1e-128", "65,6,1e135",
           "70,6,3.402824e38", "70,6,1e-50", "60,6,1e309", "60,6,1e-999",
           "10,6,1,,,,,not-a-guid", "10,6,1,,,,,,18446744073709551616",
           "10,6,1,,,,,,-1", "10,6,1,,,,,,1junk", "10,6,1,,,,,,,",
           "10,6,1,,,,,,@", "10,6,1,,,,,,@1969-12-31T23:59:59Z",
           "10,6,1,,,,,,@2023-02-29T00:00:00Z",
           "10,6,1,,,,,,@2100-02-29T00:00:00Z",
           "10,6,1,,,,,,@2024-00-01T00:00:00Z",
           "10,6,1,,,,,,@2024-04-31T00:00:00Z",
           "10,6,1,,,,,,@2024-01-01T24:00:00Z",
           "10,6,1,,,,,,@2024-01-01T00:60:00Z",
           "10,6,1,,,,,,@2024-01-01T00:00:60Z",
           "10,6,1,,,,,,@2024-01-01T00:00:00.Z",
           "10,6,1,,,,,,@2024-01-01T00:00:00.1234567890Z",
           "10,6,1,,,,,,@2024-01-01T00:00:00+01:00",
           "10,6,1,,,,,,@2554-12-31T00:00:00Z",
           "10,6,1,,,,,,@2024-01-01T00:00:00Zjunk"}) {
        vscpEventEx event{};
        if (parseMeasurementCommand(arguments, interfaceGuid.data(), event)) {
            std::cerr << "Unexpectedly accepted: " << arguments << '\n';
            assert(false);
        }
    }
    vscpEventEx event{};
    assert(!parseMeasurementCommand("1040,6," + std::string(484, '9'),
                                    interfaceGuid.data(), event));
}

void testTcpHandler()
{
    CControlObject control;
    CTcpipSrv& server = control.getTcpipSrv();
    mg_mgr manager;
    mg_mgr_init(&manager);
    mg_connection* connection = mg_alloc_conn(&manager);
    assert(connection);
    CClientItem client;
    client.setControlObject(&control);
    client.setConnection(connection);
    client.setConnected(true);
    client.setClientID(42);
    cguid guid;
    guid.getFromArray(interfaceGuid.data());
    client.setInterfaceGUID(guid);
    connection->fn_data = &client;

    auto send = [&](const std::string& command, const std::string& expected) {
        const std::string line = command + "\r\n";
        assert(mg_iobuf_add(&connection->recv, connection->recv.len,
                            line.data(), line.size()) == line.size());
        server.handleIncomingData(connection);
        std::string response(reinterpret_cast<char*>(connection->send.buf),
                              connection->send.len);
        if (response != expected) {
            std::cerr << command << ": expected " << expected << "got " << response;
            assert(false);
        }
        mg_iobuf_del(&connection->send, 0, connection->send.len);
    };
    send("measurement 10,6,1", MSG_NOT_ACCREDITED);
    assert(control.getUserList().addUser("measurement-reader", "", "", "", nullptr,
                                         "user", "*", "*:*"));
    client.setUserItem(control.getUserList().getUser("measurement-reader"));
    client.setAuthenticated(true);
    // Explicitly remove SEND permission, independent of the named role.
    client.getUserItem()->setUserRights(VSCP_USER_RIGHT_ALLOW_RCV_EVENT);
    send("measurement 10,6,1", MSG_NO_RIGHTS_ERROR);
    assert(control.getUserList().addUser("measurement-limited", "", "", "", nullptr,
                                         "admin", "*", "10:6"));
    client.setUserItem(control.getUserList().getUser("measurement-limited"));
    client.setAuthenticated(true);
    send("measurement 10,7,1", MSG_MOT_ALLOWED_TO_SEND_EVENT);
    assert(control.getClientList().getMainReceiveQueueSize() == 0);
    assert(control.getUserList().addUser("measurement-admin", "", "", "", nullptr,
                                         "admin", "*", "*:*"));
    client.setUserItem(control.getUserList().getUser("measurement-admin"));
    client.setAuthenticated(true);
    send("measurement 10,6,broken", MSG_PARAMETER_ERROR);
    send("measurement", MSG_PARAMETER_ERROR);
    assert(control.getClientList().getMainReceiveQueueSize() == 0);
    send("MeAsUrEmEnT 1060,6,1.5,1,2,3,4,,@2024-02-29T00:00:00.123456789Z", MSG_OK);
    vscpEvent* event = control.getClientList().getEventFromClientMainReceiveQueue(true);
    assert(event && event->obid == 42 && event->vscp_class == 1060 && event->vscp_type == 6);
    assert(event->timestamp_ns == 1709164800123456789ULL);
    assert(event->year == 0xffff && event->month == 0xff);
    assert(std::equal(interfaceGuid.begin(), interfaceGuid.end(), event->GUID));
    const std::array<uint8_t, 12> expected = {2, 3, 4, 1, 0x3f, 0xf8, 0, 0, 0, 0, 0, 0};
    assert(event->sizeData == expected.size());
    assert(std::equal(expected.begin(), expected.end(), event->pdata));
    vscp_deleteEvent_v2(&event);
    assert(client.getStatistics().cntReceiveFrames == 1);
    assert(client.getStatistics().cntReceiveData == expected.size());
    assert(control.getClientList().getMainReceiveQueueSize() == 0);
    connection->fn_data = nullptr;
    mg_mgr_free(&manager);
}

} // namespace

int main()
{
    testEncodings();
    testDefaultsAndTimestamps();
    testInvalidInput();
    testTcpHandler();
    std::cout << "Measurement encodings, timestamps, validation and TCP handling passed\n";
}
