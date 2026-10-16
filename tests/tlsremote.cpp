// End-to-end TLS test using the VSCP remote TCP interface implementation.

#include <vscpremotetcpif.h>
#include <sodium.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

uint16_t freePort()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
        throw std::runtime_error("unable to allocate a TCP port");
    }
    socklen_t length = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        close(fd);
        throw std::runtime_error("unable to read the allocated TCP port");
    }
    close(fd);
    return ntohs(address.sin_port);
}

std::string passwordHash(const std::string& password)
{
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("unable to create password hash");
    }
    return hash;
}

class Daemon {
  public:
    Daemon(const std::string& executable,
           const std::string& certificate,
           const std::string& key)
    {
        char folderTemplate[] = "/tmp/vscpd-tls-test-XXXXXX";
        if (!mkdtemp(folderTemplate)) {
            throw std::runtime_error("mkdtemp failed");
        }
        m_folder = folderTemplate;
        m_port = freePort();
        m_password = "tls-test-password";

        std::ofstream config(m_folder + "/vscpd.json");
        config << "{\n"
               << "  \"logging\": {\"file-enable-log\": false,\n"
               << "              \"syslog-enable-log\": false,\n"
               << "              \"udp-enable-log\": false,\n"
               << "              \"console-enable-log\": true,\n"
               << "              \"console-log-level\": \"info\"},\n"
               << "  \"security\": {\"vscpkey\": "
               << "\"A4A86F7D7E119BA3F0CD06881E371B989B33B6D606A863B633EF529D64544F8E\"},\n"
               << "  \"tcpip\": {\n"
               << "    \"interface-address\": \"tls://127.0.0.1:" << m_port << "\",\n"
               << "    \"ssl-options\": {\"cafile\": \"\", \"certfile\": \""
               << certificate << "\", \"keyfile\": \"" << key
               << "\", \"name\": \"\"}\n"
               << "  },\n"
               << "  \"remoteuser\": [{\"username\": \"tlsuser\", \"password\": \""
               << passwordHash(m_password)
               << "\", \"privilege\": \"admin\", \"allowed_remotes\": \"\","
               << " \"allowed_events\": \"*:*\"}]\n"
               << "}\n";
        config.close();

        m_pid = fork();
        if (m_pid == 0) {
            FILE* log = freopen((m_folder + "/vscpd.log").c_str(), "w", stdout);
            if (!log) {
                _exit(125);
            }
            dup2(STDOUT_FILENO, STDERR_FILENO);
            if (chdir(m_folder.c_str()) != 0) {
                _exit(126);
            }
            std::string absoluteExecutable = std::filesystem::absolute(executable).string();
            execl(absoluteExecutable.c_str(), absoluteExecutable.c_str(), "-s", "-r",
                  m_folder.c_str(), "-c", (m_folder + "/vscpd.json").c_str(),
                  static_cast<char*>(nullptr));
            _exit(127);
        }
        if (m_pid < 0) {
            throw std::runtime_error("fork failed");
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        while (std::chrono::steady_clock::now() < deadline) {
            int status = 0;
            if (waitpid(m_pid, &status, WNOHANG) == m_pid) {
                m_pid = -1;
                throw std::runtime_error("vscpd exited while starting");
            }
            VscpRemoteTcpIf probe;
            probe.setTLSOptions(false);
            if (probe.doCmdOpen("stcp://127.0.0.1:" + std::to_string(m_port),
                                "tlsuser", m_password) == VSCP_ERROR_SUCCESS) {
                probe.doCmdClose();
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        stop();
        throw std::runtime_error("vscpd did not start");
    }

    ~Daemon()
    {
        stop();
        if (!std::getenv("VSCP_KEEP_TEMP")) {
            std::error_code ignored;
            std::filesystem::remove_all(m_folder, ignored);
        }
    }

    uint16_t port() const { return m_port; }
    const std::string& password() const { return m_password; }

    void stop()
    {
        if (m_pid <= 0) {
            return;
        }
        kill(m_pid, SIGTERM);
        int status = 0;
        for (int i = 0; i < 100 && waitpid(m_pid, &status, WNOHANG) == 0; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (waitpid(m_pid, &status, WNOHANG) == 0) {
            kill(m_pid, SIGKILL);
            waitpid(m_pid, &status, 0);
        }
        m_pid = -1;
    }

  private:
    std::string m_folder;
    std::string m_password;
    uint16_t m_port = 0;
    pid_t m_pid = -1;
};

void checkTlsConnection(const Daemon& daemon, const std::string& certificate)
{
    VscpRemoteTcpIf client;
    client.setTLSOptions(false, certificate);
    if (client.doCmdOpen("127.0.0.1:" + std::to_string(daemon.port()),
                         "tlsuser", daemon.password()) != VSCP_ERROR_SUCCESS) {
        throw std::runtime_error("explicit TLS connection failed");
    }
    if (client.doCmdNOOP() != VSCP_ERROR_SUCCESS) {
        throw std::runtime_error("TLS NOOP failed");
    }
    uint8_t major = 0;
    uint8_t minor = 0;
    uint8_t patch = 0;
    if (client.doCmdVersion(&major, &minor, &patch) != VSCP_ERROR_SUCCESS) {
        throw std::runtime_error("TLS VERSION failed");
    }
    if (client.doCmdClose() != VSCP_ERROR_SUCCESS) {
        throw std::runtime_error("TLS close failed");
    }

    VscpRemoteTcpIf prefixed;
    prefixed.setTLSOptions(false, certificate);
    if (prefixed.doCmdOpen("stcp://127.0.0.1:" + std::to_string(daemon.port()),
                           "tlsuser", daemon.password()) != VSCP_ERROR_SUCCESS ||
        prefixed.doCmdNOOP() != VSCP_ERROR_SUCCESS) {
        throw std::runtime_error("stcp-prefixed TLS connection failed");
    }
    prefixed.doCmdClose();

    VscpRemoteTcpIf plain;
    plain.setConnectTimeout(2);
    if (plain.doCmdOpen("tcp://127.0.0.1:" + std::to_string(daemon.port()),
                        "tlsuser", daemon.password()) == VSCP_ERROR_SUCCESS) {
        plain.doCmdClose();
        throw std::runtime_error("plain connection unexpectedly succeeded");
    }
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 4) {
        std::cerr << "usage: " << argv[0] << " <vscpd> <certificate> <private-key>\n";
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        std::cerr << "sodium_init failed\n";
        return 2;
    }
    try {
        const std::string executable = std::filesystem::absolute(argv[1]).string();
        const std::string certificate = std::filesystem::absolute(argv[2]).string();
        const std::string key = std::filesystem::absolute(argv[3]).string();
        Daemon daemon(executable, certificate, key);
        checkTlsConnection(daemon, certificate);
        std::cout << "TLS remote TCP test passed\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "TLS remote TCP test failed: " << error.what() << "\n";
        return 1;
    }
}
