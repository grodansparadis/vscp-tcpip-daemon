// binaryserver.cpp: black-box test of the binary protocol against a running
// vscpd. The daemon is started with a temporary configuration and all traffic
// goes over a real TCP connection.
//
// Usage: binaryserver_test <path-to-vscpd>
//
// This file is part of the VSCP (https://www.vscp.org)
//
// Copyright (C) 2000-2026 Ake Hedman,
// Ake Hedman, the VSCP project, <info@vscp.org>
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version
// 2 of the License, or (at your option) any later version.

#include "version.h"
#include "vscp-binary-protocol.h"

#include <sodium.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;
using Clock = std::chrono::steady_clock;

constexpr uint16_t cmdNoop = 0;
constexpr uint16_t cmdQuit = 1;
constexpr uint16_t cmdUser = 2;
constexpr uint16_t cmdPass = 3;
constexpr uint16_t cmdSend = 5;
constexpr uint16_t cmdRetr = 6;
constexpr uint16_t cmdRcvloop = 7;
constexpr uint16_t cmdQuitloop = 8;
constexpr uint16_t cmdClrall = 10;
constexpr uint16_t cmdVersion = 16;
constexpr uint16_t cmdText = 24;
constexpr uint16_t cmdAsync = 0xffff;

constexpr uint16_t errSuccess = 0;
constexpr uint16_t errRcvEmpty = 19;
constexpr uint16_t errParameter = 34;
constexpr uint16_t errInvalidFrame = 63;
constexpr uint16_t errNotAuthorized = 74;

int failures = 0;

class TestFailure : public std::runtime_error {
  public:
    using std::runtime_error::runtime_error;
};

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            std::ostringstream where;                                          \
            where << __FILE__ << ":" << __LINE__ << ": " #condition;           \
            throw TestFailure(where.str());                                    \
        }                                                                      \
    } while (0)

struct Frame {
    Bytes data;

    uint8_t type() const { return data[0] >> 4; }
    uint8_t encryption() const { return data[0] & 0x0f; }
    uint16_t command() const { return vscp_binary::read16(data.data() + 1); }
    uint16_t error() const { return vscp_binary::read16(data.data() + 3); }
    Bytes arguments() const { return Bytes(data.begin() + 5, data.end() - 2); }
    uint16_t eventClass() const { return vscp_binary::read16(data.data() + 14); }
    uint16_t eventType() const { return vscp_binary::read16(data.data() + 16); }
    Bytes eventData() const { return Bytes(data.begin() + 36, data.end() - 2); }
};

Bytes commandFrame(uint16_t code, const Bytes& arguments = {})
{
    Bytes frame{0xe0};
    vscp_binary::append(frame, code, 2);
    frame.insert(frame.end(), arguments.begin(), arguments.end());
    frame.resize(frame.size() + 2);
    vscp_binary::setCrc(frame);
    return frame;
}

Bytes eventFrame(uint16_t vscpClass, uint16_t vscpType, const Bytes& data)
{
    Bytes frame{0x10};
    vscp_binary::append(frame, 0x0100, 2);
    vscp_binary::append(frame, 0x1122334455667788ULL, 8);
    vscp_binary::append(frame, 0, 3);
    vscp_binary::append(frame, vscpClass, 2);
    vscp_binary::append(frame, vscpType, 2);
    for (uint8_t i = 0; i < 16; ++i) {
        frame.push_back(i);
    }
    vscp_binary::append(frame, data.size(), 2);
    frame.insert(frame.end(), data.begin(), data.end());
    frame.resize(frame.size() + 2);
    vscp_binary::setCrc(frame);
    return frame;
}

// SEND takes the event frame without the lead byte and without the CRC.
Bytes sendArguments(const Bytes& event)
{
    return Bytes(event.begin() + 1, event.end() - 2);
}

std::string hex(const uint8_t* data, size_t size)
{
    static const char digits[] = "0123456789ABCDEF";
    std::string out;
    for (size_t i = 0; i < size; ++i) {
        out += digits[data[i] >> 4];
        out += digits[data[i] & 0x0f];
    }
    return out;
}

uint16_t freePort()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof(address);
    if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&address), size) != 0 ||
        getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
        throw std::runtime_error("unable to find a free port");
    }
    close(fd);
    return ntohs(address.sin_port);
}

class Client {
  public:
    Client(uint16_t port, const uint8_t* key) : m_key(key)
    {
        m_fd = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (m_fd < 0 ||
            connect(m_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
            if (m_fd >= 0) close(m_fd);
            throw std::runtime_error("connect failed");
        }
        int one = 1;
        setsockopt(m_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        m_welcome = readUntil("+OK - Success.\r\n");
    }

    ~Client()
    {
        if (m_fd >= 0) close(m_fd);
    }

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    const std::string& welcome() const { return m_welcome; }

    void sendRaw(const Bytes& data)
    {
        size_t sent = 0;
        while (sent < data.size()) {
            ssize_t n = ::send(m_fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
            CHECK(n > 0);
            sent += static_cast<size_t>(n);
        }
    }

    void sendText(const std::string& text)
    {
        sendRaw(Bytes(text.begin(), text.end()));
    }

    void enterBinary()
    {
        sendText("BINARY\r\n");
        CHECK(readUntil("\r\n") == "+OK - Success.\r\n");
    }

    Bytes wire(const Bytes& frame, uint8_t encryption = 3) const
    {
        Bytes out;
        CHECK(vscp_binary::encode(frame, encryption, m_key, out));
        return out;
    }

    void sendFrame(const Bytes& frame, uint8_t encryption = 3)
    {
        sendRaw(wire(frame, encryption));
    }

    Frame readFrame(int timeoutMs = 3000)
    {
        fill(vscp_binary::headerSize + 1, timeoutMs);
        size_t length = 0;
        CHECK(vscp_binary::parseHeader(m_buffer.data(), length));
        fill(vscp_binary::headerSize + length, timeoutMs);
        Bytes body(m_buffer.begin() + vscp_binary::headerSize,
                   m_buffer.begin() + vscp_binary::headerSize + length);
        m_buffer.erase(m_buffer.begin(),
                       m_buffer.begin() + vscp_binary::headerSize + length);
        Frame frame;
        CHECK(vscp_binary::decode(body, m_key, frame.data));
        return frame;
    }

    // Reads the next reply. Events and receive loop keep-alives are queued.
    Frame readReply(int timeoutMs = 3000)
    {
        while (true) {
            Frame frame = readFrame(timeoutMs);
            if (frame.type() <= 1) {
                m_events.push_back(frame);
            }
            else if (!(m_inLoop && frame.command() == cmdNoop)) {
                CHECK(frame.type() == 15);
                return frame;
            }
        }
    }

    Frame readEvent(uint16_t eventClass, uint16_t eventType, int timeoutMs = 3000)
    {
        // Skip unrelated events such as the daemon's periodic heartbeats.
        while (true) {
            while (m_events.empty()) {
                Frame frame = readFrame(timeoutMs);
                if (frame.type() <= 1) {
                    m_events.push_back(frame);
                }
                else {
                    CHECK(frame.type() == 15 && frame.command() == cmdNoop);
                }
            }
            Frame event = m_events.front();
            m_events.pop_front();
            if (event.eventClass() == eventClass && event.eventType() == eventType) {
                return event;
            }
        }
    }

    Frame command(uint16_t code, const Bytes& arguments = {}, uint8_t encryption = 3)
    {
        sendFrame(commandFrame(code, arguments), encryption);
        Frame reply = readReply();
        CHECK(reply.command() == code);
        return reply;
    }

    void login(const std::string& user, const std::string& password)
    {
        std::string credentials = user + ":" + password;
        CHECK(command(cmdUser, Bytes(credentials.begin(), credentials.end())).error() ==
              errSuccess);
    }

    void setInLoop(bool inLoop) { m_inLoop = inLoop; }

    bool closedByPeer(int timeoutMs = 3000)
    {
        auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (Clock::now() < deadline) {
            pollfd descriptor{m_fd, POLLIN, 0};
            if (poll(&descriptor, 1, 100) > 0) {
                uint8_t data[512];
                ssize_t n = recv(m_fd, data, sizeof(data), 0);
                if (n <= 0) return true;
            }
        }
        return false;
    }

    bool silent(int timeoutMs)
    {
        if (!m_buffer.empty()) return false;
        pollfd descriptor{m_fd, POLLIN, 0};
        return poll(&descriptor, 1, timeoutMs) == 0;
    }

    std::string readUntil(const std::string& terminator)
    {
        while (true) {
            std::string text(m_buffer.begin(), m_buffer.end());
            size_t position = text.find(terminator);
            if (position != std::string::npos) {
                m_buffer.erase(m_buffer.begin(),
                               m_buffer.begin() + position + terminator.size());
                return text.substr(0, position + terminator.size());
            }
            fill(m_buffer.size() + 1, 5000);
        }
    }

  private:
    void fill(size_t size, int timeoutMs)
    {
        auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
        while (m_buffer.size() < size) {
            int left = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                          deadline - Clock::now())
                                          .count());
            CHECK(left > 0);
            pollfd descriptor{m_fd, POLLIN, 0};
            CHECK(poll(&descriptor, 1, left) > 0);
            uint8_t data[4096];
            ssize_t n = recv(m_fd, data, sizeof(data), 0);
            CHECK(n > 0);
            m_buffer.insert(m_buffer.end(), data, data + n);
        }
    }

    int m_fd = -1;
    const uint8_t* m_key;
    bool m_inLoop = false;
    Bytes m_buffer;
    std::deque<Frame> m_events;
    std::string m_welcome;
};

class Daemon {
  public:
    explicit Daemon(const std::string& executable)
    {
        char folderTemplate[] = "/tmp/vscpd-binaryserver-XXXXXX";
        if (!mkdtemp(folderTemplate)) throw std::runtime_error("mkdtemp failed");
        m_folder = folderTemplate;
        randombytes_buf(m_key, sizeof(m_key));
        port = freePort();
        password = randomText();
        readerPassword = randomText();

        std::ofstream config(m_folder + "/vscpd.json");
        config << "{\n"
               << "  \"guid\": \"FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:01\",\n"
               << "  \"logging\": {\"file-enable-log\": false, \"syslog-enable-log\": false,\n"
               << "              \"udp-enable-log\": false, \"console-enable-log\": true,\n"
               << "              \"console-log-level\": \"info\"},\n"
               << "  \"security\": {\"vscpkey\": \"" << hex(m_key, sizeof(m_key)) << "\"},\n"
               << "  \"tcpip\": {\"interface-address\": \"tcp://127.0.0.1:" << port
               << "\"},\n"
               << "  \"remoteuser\": [\n"
               << user("admin", password, "admin") << ",\n"
               << user("reader", readerPassword, "receive-events") << "\n"
               << "  ]\n"
               << "}\n";
        config.close();

        std::string log = m_folder + "/vscpd.log";
        std::string configPath = m_folder + "/vscpd.json";
        m_pid = fork();
        if (m_pid == 0) {
            FILE* out = freopen(log.c_str(), "w", stdout);
            (void)out;
            dup2(STDOUT_FILENO, STDERR_FILENO);
            if (chdir(m_folder.c_str()) != 0) _exit(126);
            execl(executable.c_str(), executable.c_str(), "-s", "-r", m_folder.c_str(),
                  "-c", configPath.c_str(), static_cast<char*>(nullptr));
            _exit(127);
        }
        if (m_pid < 0) throw std::runtime_error("fork failed");

        auto deadline = Clock::now() + std::chrono::seconds(15);
        while (true) {
            int status = 0;
            if (waitpid(m_pid, &status, WNOHANG) == m_pid) {
                m_pid = -1;
                printLog();
                removeFolder();
                throw std::runtime_error("vscpd exited during start");
            }
            try {
                Client probe(port, m_key);
                break;
            }
            catch (const std::exception&) {
                if (Clock::now() > deadline) {
                    kill(m_pid, SIGKILL);
                    waitpid(m_pid, &status, 0);
                    printLog();
                    removeFolder();
                    throw std::runtime_error("vscpd did not start");
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    ~Daemon()
    {
        if (m_pid > 0) {
            kill(m_pid, SIGTERM);
            int status = 0;
            for (int i = 0; i < 100 && waitpid(m_pid, &status, WNOHANG) == 0; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (waitpid(m_pid, &status, WNOHANG) == 0) {
                kill(m_pid, SIGKILL);
                waitpid(m_pid, &status, 0);
            }
        }
        if (failures) printLog();
        removeFolder();
    }

    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    const uint8_t* key() const { return m_key; }

    uint16_t port = 0;
    std::string password;
    std::string readerPassword;

  private:
    static std::string randomText()
    {
        uint8_t data[16];
        randombytes_buf(data, sizeof(data));
        return hex(data, sizeof(data));
    }

    static std::string user(const std::string& name,
                            const std::string& secret,
                            const std::string& privilege)
    {
        char hash[crypto_pwhash_STRBYTES];
        if (crypto_pwhash_str(hash, secret.c_str(), secret.size(),
                              crypto_pwhash_OPSLIMIT_INTERACTIVE,
                              crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
            throw std::runtime_error("crypto_pwhash_str failed");
        }
        return "    {\"username\": \"" + name + "\", \"password\": \"" + hash +
               "\", \"privilege\": \"" + privilege +
               "\", \"allowed_remotes\": \"\", \"allowed_events\": \"*:*\"}";
    }

    void removeFolder() const
    {
        if (!std::getenv("VSCP_KEEP_TEMP")) {
            std::error_code ignored;
            std::filesystem::remove_all(m_folder, ignored);
        }
    }

    void printLog() const
    {
        std::ifstream log(m_folder + "/vscpd.log");
        std::string text((std::istreambuf_iterator<char>(log)),
                         std::istreambuf_iterator<char>());
        if (text.size() > 4000) text = text.substr(text.size() - 4000);
        std::cerr << "---- vscpd log ----\n" << text << "-------------------\n";
    }

    std::string m_folder;
    uint8_t m_key[32];
    pid_t m_pid = -1;
};

struct Fixture {
    Daemon& daemon;

    std::unique_ptr<Client> connect(bool login = true)
    {
        auto client = std::make_unique<Client>(daemon.port, daemon.key());
        client->enterBinary();
        if (login) client->login("admin", daemon.password);
        return client;
    }
};

void testWelcomeAndModes(Fixture& fixture)
{
    auto client = fixture.connect(false);
    CHECK(client->welcome().find('\0') == std::string::npos);
    for (uint8_t encryption = 0; encryption <= 3; ++encryption) {
        Frame reply = client->command(cmdNoop, {}, encryption);
        CHECK(reply.error() == errSuccess);
        CHECK(reply.encryption() == encryption);
    }
}

void testVersion(Fixture& fixture)
{
    Frame reply = fixture.connect(false)->command(cmdVersion);
    CHECK(reply.error() == errSuccess);
    Bytes arguments = reply.arguments();
    CHECK(arguments.size() == 10);
    CHECK(vscp_binary::read16(arguments.data()) == VSCPD_VERSION_MAJOR);
    CHECK(vscp_binary::read16(arguments.data() + 2) == VSCPD_VERSION_MINOR);
    CHECK(vscp_binary::read16(arguments.data() + 4) == VSCPD_VERSION_PATCH);
}

void testAuthentication(Fixture& fixture)
{
    auto client = fixture.connect(false);
    CHECK(client->command(cmdRetr).error() == errNotAuthorized);
    CHECK(client->command(cmdNoop).error() == errSuccess);

    std::string name = "admin";
    CHECK(client->command(cmdUser, Bytes(name.begin(), name.end())).error() == errSuccess);
    std::string& secret = fixture.daemon.password;
    CHECK(client->command(cmdPass, Bytes(secret.begin(), secret.end())).error() ==
          errSuccess);
    CHECK(client->command(cmdClrall).error() == errSuccess);

    auto intruder = fixture.connect(false);
    std::string wrong = "admin:wrong";
    intruder->sendFrame(commandFrame(cmdUser, Bytes(wrong.begin(), wrong.end())));
    CHECK(intruder->readReply().error() == errNotAuthorized);
    CHECK(intruder->closedByPeer());
}

// Skip unrelated events such as the daemon's periodic heartbeats.
bool isRetrEvent(const Frame& frame, uint16_t eventClass, uint16_t eventType)
{
    Bytes args = frame.arguments();
    return args.size() >= 17 && vscp_binary::read16(args.data() + 13) == eventClass &&
           vscp_binary::read16(args.data() + 15) == eventType;
}

void testRights(Fixture& fixture)
{
    auto reader = std::make_unique<Client>(fixture.daemon.port, fixture.daemon.key());
    reader->enterBinary();
    reader->login("reader", fixture.daemon.readerPassword);
    Bytes event = eventFrame(20, 3, {1});
    CHECK(reader->command(cmdSend, sendArguments(event)).error() == errNotAuthorized);
    while (true) {
        Frame reply = reader->command(cmdRetr);
        if (reply.error() == errRcvEmpty) break;
        CHECK(reply.error() == errSuccess);
        CHECK(!isRetrEvent(reply, 20, 3));
    }
}

void testSendAndRetrieve(Fixture& fixture)
{
    auto sender = fixture.connect();
    auto receiver = fixture.connect();
    CHECK(receiver->command(cmdClrall).error() == errSuccess);

    Bytes data{1, 2, 3, 4, 5};
    CHECK(sender->command(cmdSend, sendArguments(eventFrame(20, 3, data))).error() ==
          errSuccess);

    Frame reply;
    for (int i = 0; i < 40; ++i) {
        reply = receiver->command(cmdRetr);
        if (reply.error() == errSuccess && isRetrEvent(reply, 20, 3)) break;
        if (reply.error() == errRcvEmpty) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    CHECK(reply.error() == errSuccess);
    Bytes arguments = reply.arguments();
    CHECK(arguments.size() == 35 + data.size());
    CHECK(vscp_binary::read16(arguments.data() + 13) == 20);
    CHECK(vscp_binary::read16(arguments.data() + 15) == 3);
    CHECK(Bytes(arguments.begin() + 35, arguments.end()) == data);

    // The sender must never get its own event back.
    while (true) {
        Frame own = sender->command(cmdRetr);
        if (own.error() == errRcvEmpty) break;
        CHECK(own.error() == errSuccess);
        CHECK(!isRetrEvent(own, 20, 3));
    }
}

void testReceiveLoopAndEventFrames(Fixture& fixture)
{
    auto sender = fixture.connect();
    auto receiver = fixture.connect();
    CHECK(receiver->command(cmdRcvloop).error() == errSuccess);
    receiver->setInLoop(true);

    Bytes data{9, 8, 7};
    Bytes event = eventFrame(10, 6, data);
    sender->sendFrame(event);
    Frame confirm = sender->readReply();
    CHECK(confirm.command() == cmdAsync);
    CHECK(confirm.error() == errSuccess);
    Bytes arguments = confirm.arguments();
    CHECK(arguments.size() == 6);
    CHECK(vscp_binary::read16(arguments.data() + 4) == vscp_binary::read16(&event[event.size() - 2]));

    Frame received = receiver->readEvent(10, 6);
    CHECK(received.type() == 1);
    CHECK(received.encryption() == 3);
    CHECK(received.eventClass() == 10);
    CHECK(received.eventType() == 6);
    CHECK(received.eventData() == data);

    CHECK(receiver->command(cmdQuitloop).error() == errSuccess);
    receiver->setInLoop(false);
    CHECK(receiver->command(cmdNoop).error() == errSuccess);
}

void testResync(Fixture& fixture)
{
    auto client = fixture.connect(false);

    Bytes garbage{0x00, 0x55, 0x01, 0xff, 0x13, 0x42, 0x55};
    Bytes request = garbage;
    Bytes noop = client->wire(commandFrame(cmdNoop));
    request.insert(request.end(), noop.begin(), noop.end());
    client->sendRaw(request);
    Frame error = client->readReply();
    CHECK(error.command() == cmdAsync && error.error() == errInvalidFrame);
    Frame reply = client->readReply();
    CHECK(reply.command() == cmdNoop && reply.error() == errSuccess);

    Bytes bad = client->wire(commandFrame(cmdNoop), 0);
    bad.back() ^= 0xff;
    bad.insert(bad.end(), noop.begin(), noop.end());
    client->sendRaw(bad);
    error = client->readReply();
    CHECK(error.command() == cmdAsync && error.error() == errInvalidFrame);
    reply = client->readReply();
    CHECK(reply.command() == cmdNoop && reply.error() == errSuccess);

    // A header that promises more data than arrives is dropped after a timeout.
    client->sendRaw({0x55, 0x2f, 0xff, 0xe0});
    error = client->readReply(5000);
    CHECK(error.command() == cmdAsync && error.error() == errInvalidFrame);
    CHECK(client->command(cmdNoop).error() == errSuccess);

    Bytes reply15{0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    vscp_binary::setCrc(reply15);
    client->sendFrame(reply15);
    error = client->readReply();
    CHECK(error.command() == cmdAsync && error.error() == errParameter);
}

void testFragmentation(Fixture& fixture)
{
    auto client = fixture.connect(false);
    Bytes request = client->wire(commandFrame(cmdNoop));
    for (uint8_t byte : request) {
        client->sendRaw({byte});
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    CHECK(client->readReply().error() == errSuccess);

    Bytes coalesced;
    for (int i = 0; i < 5; ++i) {
        Bytes one = client->wire(commandFrame(cmdNoop), static_cast<uint8_t>(i % 4));
        coalesced.insert(coalesced.end(), one.begin(), one.end());
    }
    client->sendRaw(coalesced);
    for (int i = 0; i < 5; ++i) {
        CHECK(client->readReply().error() == errSuccess);
    }
    CHECK(client->silent(200));
}

void testTextRoundTripAndQuit(Fixture& fixture)
{
    auto client = fixture.connect(false);
    CHECK(client->command(cmdText).error() == errSuccess);
    client->sendText("NOOP\r\n");
    CHECK(client->readUntil("\r\n") == "+OK - Success.\r\n");
    client->enterBinary();
    CHECK(client->command(cmdNoop).error() == errSuccess);
    CHECK(client->command(cmdQuit).error() == errSuccess);
    CHECK(client->closedByPeer());
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <path-to-vscpd>\n";
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 2;
    }
    crcInit();

    const std::vector<std::pair<const char*, std::function<void(Fixture&)>>> tests{
        {"welcome and modes", testWelcomeAndModes},
        {"version", testVersion},
        {"authentication", testAuthentication},
        {"rights", testRights},
        {"send and retrieve", testSendAndRetrieve},
        {"receive loop and event frames", testReceiveLoopAndEventFrames},
        {"resync", testResync},
        {"fragmentation", testFragmentation},
        {"text round trip and quit", testTextRoundTripAndQuit},
    };

    try {
        Daemon daemon(std::filesystem::absolute(argv[1]).string());
        Fixture fixture{daemon};
        for (const auto& test : tests) {
            try {
                test.second(fixture);
                std::cout << "ok      " << test.first << "\n";
            }
            catch (const std::exception& e) {
                ++failures;
                std::cout << "FAILED  " << test.first << ": " << e.what() << "\n";
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    std::cout << tests.size() - failures << "/" << tests.size() << " passed\n";
    return failures ? 1 : 0;
}
