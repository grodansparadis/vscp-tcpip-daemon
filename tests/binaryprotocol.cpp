#include "vscp-binary-protocol.h"

#include <cassert>
#include <iostream>

void testBinaryTcp();
void testSecureMemory();

int main()
{
    crcInit();
    uint8_t key[32] = {};
    uint8_t hmacKey[32];
    std::fill(std::begin(hmacKey), std::end(hmacKey), 0x5a);
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
            size_t length = 0;
            uint8_t version = 0xff;
            assert(vscp_binary::parseHeader(wire.data(), length, &version));
            assert(wire[0] == 0x55 &&
                   version == vscp_binary::legacyFramingVersion);
            assert(length == wire.size() - vscp_binary::headerSize);
            assert(vscp_binary::decode(wire, key, decoded));
            if (frame != decoded) {
                std::cerr << "Round trip mismatch: encryption=" << unsigned(encryption)
                          << " payload=" << size << " expected="
                          << frame.size() << " decoded=" << decoded.size()
                          << '\n';
                return 1;
            }

            if (encryption) {
                assert(vscp_binary::encode(frame, encryption, key, wire, hmacKey));
                assert(vscp_binary::parseHeader(wire.data(), length, &version));
                assert(version == vscp_binary::hmacFramingVersion);
                assert(length == wire.size() - vscp_binary::headerSize);
                assert(vscp_binary::decode(wire, key, decoded, hmacKey));
                assert(frame == decoded);

                auto badTag = wire;
                badTag.back() ^= 1;
                assert(!vscp_binary::decode(badTag, key, decoded, hmacKey));
                assert(!vscp_binary::decode(wire, key, decoded));
                uint8_t wrongHmacKey[32] = {};
                assert(!vscp_binary::decode(wire, key, decoded, wrongHmacKey));

                auto legacyDowngrade = std::vector<uint8_t>(wire.begin(),
                                                             wire.end() - 16);
                legacyDowngrade[1] &= 0x1f;
                auto legacyLength = legacyDowngrade.size() -
                                    vscp_binary::headerSize;
                legacyDowngrade[1] = static_cast<uint8_t>(
                  legacyLength >> 8);
                legacyDowngrade[2] = static_cast<uint8_t>(legacyLength);
                assert(!vscp_binary::decode(legacyDowngrade,
                                            key,
                                            decoded,
                                            hmacKey));
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
    std::vector<uint8_t> corruptCrc;
    assert(vscp_binary::encode(frame, 0, key, corruptCrc));
    corruptCrc.back() ^= 1;
    std::vector<uint8_t> decoded;
    assert(!vscp_binary::decode(corruptCrc, key, decoded));
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
          wire, key, decoded));
    }
    size_t length = 0;
    const uint8_t noop[] = {0x55, 0x00, 0x05, 0xe0};
    assert(vscp_binary::parseHeader(noop, length) && length == 5);
    const uint8_t wrongVersion[] = {0x55, 0x40, 0x05, 0xe0};
    assert(!vscp_binary::parseHeader(wrongVersion, length));
    const uint8_t wrongType[] = {0x55, 0x00, 0x05, 0x20};
    assert(!vscp_binary::parseHeader(wrongType, length));
    const uint8_t wrongSync[] = {0x54, 0x20, 0x05, 0xe0};
    assert(!vscp_binary::parseHeader(wrongSync, length));
    const uint8_t tooLong[] = {0x55, 0x30, 0x01, 0xe0};
    assert(!vscp_binary::parseHeader(tooLong, length));
    const uint8_t badAesLength[] = {0x55, 0x00, 0x22, 0xe1};
    assert(!vscp_binary::parseHeader(badAesLength, length));
    const uint8_t badHmacLength[] = {0x55, 0x20, 0x22, 0xe1};
    assert(!vscp_binary::parseHeader(badHmacLength, length));
    const uint8_t hmacOnPlaintext[] = {0x55, 0x20, 0x05, 0xe0};
    assert(!vscp_binary::parseHeader(hmacOnPlaintext, length));
    std::cout << "Binary codec: 2052 plaintext/AES round trips, event and "
                 "HMAC, malformed-frame and header checks passed\n";
    testBinaryTcp();
    testSecureMemory();
}
