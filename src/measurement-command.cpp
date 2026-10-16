#include "measurement-command.h"

#include <array>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <locale>
#include <sstream>
#include <string_view>

#include <vscphelper.h>

namespace {

bool parseUnsigned(std::string_view text, uint64_t maximum, uint64_t& value)
{
    int base = 10;
    if (text.size() > 2 && (text.substr(0, 2) == "0x" ||
                            text.substr(0, 2) == "0X")) {
        text.remove_prefix(2);
        base = 16;
    }
    auto result = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return result.ec == std::errc{} &&
           result.ptr == text.data() + text.size() && value <= maximum;
}

struct Decimal {
    bool negative = false;
    bool integerLiteral = true;
    std::string digits;
    int exponent = 0;
};

bool parseDecimal(const std::string& text, Decimal& number)
{
    size_t pos = 0;
    if (pos < text.size() && (text[pos] == '-' || text[pos] == '+')) {
        number.negative = text[pos++] == '-';
    }
    bool point = false;
    while (pos < text.size()) {
        char ch = text[pos];
        if (ch >= '0' && ch <= '9') {
            number.digits += ch;
            if (point) --number.exponent;
        }
        else if (ch == '.' && !point) {
            point = true;
            number.integerLiteral = false;
        }
        else {
            break;
        }
        ++pos;
    }
    if (number.digits.empty()) return false;
    if (pos < text.size() && (text[pos] == 'e' || text[pos] == 'E')) {
        number.integerLiteral = false;
        ++pos;
        bool negative = false;
        if (pos < text.size() && (text[pos] == '-' || text[pos] == '+')) {
            negative = text[pos++] == '-';
        }
        uint64_t exponent = 0;
        auto result = std::from_chars(text.data() + pos,
                                      text.data() + text.size(), exponent);
        if (result.ec != std::errc{} || result.ptr != text.data() + text.size() ||
            exponent > 10000) return false;
        number.exponent += negative ? -static_cast<int>(exponent) :
                                      static_cast<int>(exponent);
        pos = text.size();
    }
    return pos == text.size();
}

void writeBigEndian(uint8_t* data, uint64_t value, size_t bytes)
{
    for (size_t i = bytes; i > 0; --i) {
        data[i - 1] = static_cast<uint8_t>(value);
        value >>= 8;
    }
}

bool writeSigned(uint8_t* data, const Decimal& number, size_t maximum,
                 uint16_t& bytes)
{
    uint64_t magnitude = 0;
    uint64_t limit = uint64_t{1} << (maximum * 8 - 1);
    if (!parseUnsigned(number.digits, limit - (number.negative ? 0 : 1),
                       magnitude)) return false;
    int64_t value = number.negative ? -static_cast<int64_t>(magnitude) :
                                     static_cast<int64_t>(magnitude);
    bytes = 1;
    while (bytes < maximum &&
           (value < -(int64_t{1} << (bytes * 8 - 1)) ||
            value >= (int64_t{1} << (bytes * 8 - 1)))) {
        ++bytes;
    }
    writeBigEndian(data, static_cast<uint64_t>(value), bytes);
    return true;
}

bool leapYear(unsigned year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

bool parseTimestamp(std::string_view text, uint64_t& timestamp)
{
    if (text.empty()) {
        timestamp = vscp_makeTimeStampNs();
        return true;
    }
    if (text.front() != '@') {
        return parseUnsigned(text, std::numeric_limits<uint64_t>::max(), timestamp);
    }
    text.remove_prefix(1);
    if (text.size() < 19 || text[4] != '-' || text[7] != '-' ||
        text[10] != 'T' || text[13] != ':' || text[16] != ':') return false;
    const size_t offsets[] = {0, 5, 8, 11, 14, 17};
    std::array<unsigned, 6> fields{};
    for (size_t i = 0; i < fields.size(); ++i) {
        size_t width = i == 0 ? 4 : 2;
        auto part = text.substr(offsets[i], width);
        for (char ch : part) {
            if (ch < '0' || ch > '9') return false;
            fields[i] = fields[i] * 10 + static_cast<unsigned>(ch - '0');
        }
    }
    unsigned year = fields[0], month = fields[1], day = fields[2];
    if (year < 1970 || year > 2554 || month < 1 || month > 12 ||
        fields[3] > 23 || fields[4] > 59 || fields[5] > 59) return false;
    std::array<unsigned, 12> monthDays = {31, 28, 31, 30, 31, 30,
                                         31, 31, 30, 31, 30, 31};
    if (leapYear(year)) monthDays[1] = 29;
    if (day < 1 || day > monthDays[month - 1]) return false;
    uint64_t days = day - 1;
    for (unsigned y = 1970; y < year; ++y) days += leapYear(y) ? 366 : 365;
    for (unsigned m = 1; m < month; ++m) days += monthDays[m - 1];
    uint64_t seconds = days * 86400 + fields[3] * 3600 +
                       fields[4] * 60 + fields[5];
    text.remove_prefix(19);
    uint64_t fraction = 0;
    if (!text.empty() && text.front() == '.') {
        text.remove_prefix(1);
        size_t digits = 0;
        while (!text.empty() && text.front() >= '0' && text.front() <= '9') {
            if (++digits > 9) return false;
            fraction = fraction * 10 + static_cast<unsigned>(text.front() - '0');
            text.remove_prefix(1);
        }
        if (digits == 0) return false;
        for (; digits < 9; ++digits) fraction *= 10;
    }
    if (!text.empty() && text != "Z" && text != "+00:00") return false;
    if (seconds > (std::numeric_limits<uint64_t>::max() - fraction) / 1000000000) {
        return false;
    }
    timestamp = seconds * 1000000000 + fraction;
    return true;
}

} // namespace

bool parseMeasurementCommand(const std::string& arguments,
                             const uint8_t* interfaceGuid,
                             vscpEventEx& event)
{
    std::array<std::string, 9> fields;
    size_t count = 0, start = 0;
    do {
        if (count == fields.size()) return false;
        size_t end = arguments.find(',', start);
        fields[count] = arguments.substr(start, end - start);
        vscp_trim(fields[count++]);
        if (end == std::string::npos) break;
        start = end + 1;
    } while (true);
    if (count < 3) return false;

    uint64_t vscpClass = 0, type = 0;
    if (!parseUnsigned(fields[0], 65535, vscpClass) ||
        !parseUnsigned(fields[1], vscpClass < 512 ? 255 : 65535, type)) return false;
    bool coded = vscpClass >= 10 && vscpClass <= 14;
    bool zone = (vscpClass >= 65 && vscpClass <= 69) ||
                (vscpClass >= 85 && vscpClass <= 89);
    bool raw32 = vscpClass >= 70 && vscpClass <= 74;
    bool raw64 = vscpClass >= 60 && vscpClass <= 64;
    bool string = vscpClass == 1040;
    bool level2 = string || vscpClass == 1060;
    if (!coded && !zone && !raw32 && !raw64 && !level2) return false;

    std::array<uint64_t, 4> metadata{};
    for (size_t i = 0; i < metadata.size(); ++i) {
        if (!fields[i + 3].empty() &&
            !parseUnsigned(fields[i + 3], 255, metadata[i])) return false;
    }
    uint8_t unit = static_cast<uint8_t>(metadata[0]);
    uint8_t index = static_cast<uint8_t>(metadata[1]);
    if ((coded && (unit > 3 || index > 7 || metadata[2] || metadata[3])) ||
        (zone && unit > 3) ||
        ((raw32 || raw64) && (unit || index || metadata[2] || metadata[3]))) {
        return false;
    }

    Decimal number;
    if (fields[2].size() > 483 || !parseDecimal(fields[2], number)) return false;
    event = {};
    event.head = VSCP_HEADER16_FRAME_VERSION_UNIX_NS | VSCP_PRIORITY_NORMAL;
    event.year = 0xffff;
    event.month = 0xff;
    event.vscp_class = static_cast<uint16_t>(vscpClass);
    event.vscp_type = static_cast<uint16_t>(type);
    if (fields[7].empty() || fields[7] == "-") {
        std::memcpy(event.GUID, interfaceGuid, 16);
    }
    else if (!vscp_parseGuid(event.GUID, fields[7])) {
        return false;
    }
    if (!parseTimestamp(fields[8], event.timestamp_ns)) return false;

    if (level2 || zone) {
        event.data[0] = index;
        event.data[1] = static_cast<uint8_t>(metadata[2]);
        event.data[2] = static_cast<uint8_t>(metadata[3]);
    }
    if (level2) event.data[3] = unit;
    if (string) {
        event.sizeData = static_cast<uint16_t>(4 + fields[2].size() + 1);
        std::memcpy(event.data + 4, fields[2].c_str(), fields[2].size() + 1);
        return true;
    }
    if (zone) {
        size_t first = number.digits.find_first_not_of('0');
        number.digits = first == std::string::npos ? "0" : number.digits.substr(first);
        if (number.digits == "0") number.exponent = 0;
        while (number.digits.size() > 1 && number.digits.back() == '0' &&
               number.exponent < 127) {
            number.digits.pop_back();
            ++number.exponent;
        }
        if (number.exponent > 127) {
            if (number.exponent - 127 > 7 ||
                number.digits.size() + (number.exponent - 127) > 7) return false;
            number.digits.append(number.exponent - 127, '0');
            number.exponent = 127;
        }
        if (number.exponent < -127 || number.exponent > 127) return false;
        event.data[3] = VSCP_DATACODING_NORMALIZED | (unit << 3);
        event.data[4] = static_cast<uint8_t>(number.exponent < 0 ?
                                            0x80 | -number.exponent : number.exponent);
        uint16_t bytes = 0;
        if (!writeSigned(event.data + 5, number, 3, bytes)) return false;
        event.sizeData = 5 + bytes;
        return true;
    }
    if (coded && number.integerLiteral) {
        event.data[0] = VSCP_DATACODING_INTEGER | (unit << 3) | index;
        uint16_t bytes = 0;
        if (!writeSigned(event.data + 1, number, 7, bytes)) return false;
        event.sizeData = 1 + bytes;
        return true;
    }

    double value = 0;
    std::istringstream input(fields[2]);
    input.imbue(std::locale::classic());
    input >> value;
    if (input.fail() || !std::isfinite(value) ||
        (value == 0 && number.digits.find_first_not_of('0') != std::string::npos)) {
        return false;
    }
    size_t offset = level2 ? 4 : coded ? 1 : 0;
    size_t bytes = (coded || raw32) ? 4 : 8;
    uint64_t bits = 0;
    if (bytes == 4) {
        if (std::abs(value) > std::numeric_limits<float>::max()) return false;
        float single = static_cast<float>(value);
        if (single == 0 && value != 0) return false;
        uint32_t singleBits = 0;
        std::memcpy(&singleBits, &single, sizeof(singleBits));
        bits = singleBits;
    }
    else {
        std::memcpy(&bits, &value, sizeof(bits));
    }
    if (coded) event.data[0] = VSCP_DATACODING_SINGLE | (unit << 3) | index;
    writeBigEndian(event.data + offset, bits, bytes);
    event.sizeData = static_cast<uint16_t>(offset + bytes);
    return true;
}
