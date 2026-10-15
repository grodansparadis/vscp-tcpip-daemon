#include "vscp-binary-protocol.h"

#include <cassert>
#include <iostream>

void testBinaryTcp();

int main()
{
    crcInit();
    uint8_t key[32] = {};
    for (uint8_t encryption = 0; encryption <= 3; ++encryption) {
        for (size_t size = 0; size <= 512; ++size) {
            std::vector<uint8_t> arguments(size, 0x42);
            std::vector<uint8_t> frame(5 + size, 0);
            assert(VSCP_ERROR_SUCCESS == vscp_writeCommandToFrame(
              frame.data(), frame.size(), 2,
              arguments.empty() ? nullptr : arguments.data(), size));
            vscp_binary::setCrc(frame);
            frame[0] |= encryption;
            std::vector<uint8_t> wire, decoded;
            assert(vscp_binary::encode(frame, encryption, key, wire));
            assert(vscp_binary::read16(wire.data()) == wire.size() - 2);
            assert(vscp_binary::decode(
              std::vector<uint8_t>(wire.begin() + 2, wire.end()), key, decoded));
            if (frame != decoded) {
                std::cerr << "Round trip mismatch: encryption=" << unsigned(encryption)
                          << " payload=" << size << " expected="
                          << frame.size() << " decoded=" << decoded.size()
                          << '\n';
                return 1;
            }
        }
    }
    vscpEvent event{};
    event.head = VSCP_HEADER16_FRAME_VERSION_UNIX_NS;
    event.timestamp_ns = 123456789;
    event.year = 0xffff;
    event.month = 0xff;
    event.vscp_class = 20;
    event.vscp_type = 3;
    uint8_t data[] = {0, 1, 2, '\r', '\n', 255};
    event.pdata = data;
    event.sizeData = sizeof(data);
    std::vector<uint8_t> frame(vscp_getFrameSizeFromEvent(&event), 0);
    assert(vscp_writeEventToFrame(frame.data(), frame.size(), 0, &event));
    assert(vscp_binary::validCrc(frame.data(), frame.size()));
    vscpEvent restored{};
    assert(vscp_getEventFromFrame(&restored, frame.data(), frame.size()));
    assert(restored.sizeData == event.sizeData);
    assert(restored.timestamp_ns == event.timestamp_ns);
    assert(std::equal(data, data + sizeof(data), restored.pdata));
    delete[] restored.pdata;
    frame[18] ^= 1;
    std::vector<uint8_t> decoded;
    assert(!vscp_binary::decode(frame, key, decoded));
    assert(!vscp_binary::decode({0xe0, 0, 0}, key, decoded));
    assert(!vscp_binary::decode(std::vector<uint8_t>(33, 0xe4), key, decoded));
    for (uint8_t encryption = 1; encryption <= 3; ++encryption) {
        std::vector<uint8_t> command(5, 0), wire;
        assert(vscp_writeCommandToFrame(command.data(), command.size(),
                                        0, nullptr, 0) == VSCP_ERROR_SUCCESS);
        vscp_binary::setCrc(command);
        assert(vscp_binary::encode(command, encryption, key, wire));
        wire[wire.size() - 17] ^= 0xff;
        assert(!vscp_binary::decode(
          std::vector<uint8_t>(wire.begin() + 2, wire.end()), key, decoded));
    }
    std::cout << "Binary codec: 2052 plaintext/AES round trips, event and "
                 "malformed-frame checks passed\n";
    testBinaryTcp();
}
