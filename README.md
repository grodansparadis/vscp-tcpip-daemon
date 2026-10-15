# vscp-tcpip-daemon

![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Build VSCP library on Linux](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build.yml)
[![Build VSCP library on Windows](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-windows.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-windows.yml)
[![Build VSCP library on macOS](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-macos.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-macos.yml)
[![Release](https://img.shields.io/github/release/grodansparadis/vscp-tcpip-daemon.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/releases)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

![VSCP Logo](https://github.com/grodansparadis/vscp-logo/blob/master/logo_100.png)


A central VSCP daemon that exports a VSCP tcp/ip link interface and handles level I and level II drivers.

Incoming events immediately wake the TCP/IP server's event loop to distribute
them to client queues, without waiting for a timer or blocking on the main
receive-queue semaphore. Each pass processes at most the queue size observed
at its start. The 100 ms timer remains a fallback for failed wakeups.
Clients in `RCVLOOP` mode send queued events on wakeup or polling; other clients
retrieve them with `RETR`.

## Updating the pinned VSCP source

The build downloads the VSCP sources as a source tarball pinned to one commit of
[grodansparadis/vscp](https://github.com/grodansparadis/vscp). The `vscp`
`FetchContent_Declare` in [CMakeLists.txt](CMakeLists.txt) sets the URL and
checksum:

```cmake
URL https://codeload.github.com/grodansparadis/vscp/tar.gz/<commit>
URL_HASH SHA256=<sha256 of the tarball>
```

To use a later commit:

1. Find the full 40-character commit ID you want, for example the latest on
   `master`:

   ```bash
   git ls-remote https://github.com/grodansparadis/vscp.git refs/heads/master
   ```

2. Compute the SHA256 of that commit's tarball:

   ```bash
   COMMIT=<commit>
   curl -fsSL "https://codeload.github.com/grodansparadis/vscp/tar.gz/${COMMIT}" | sha256sum
   ```

3. In `CMakeLists.txt`, replace the commit at the end of `URL` with the new
   commit ID. Replace the value after `URL_HASH SHA256=` with the 64-character
   checksum from step 2. Do not use the commit ID as the checksum. If the
   checksum doesn't match, CMake deletes every download and reports
   `Each download failed!`.

4. Reconfigure so CMake downloads the new sources, then rebuild:

   ```bash
   cmake -S . -B build
   cmake --build build
   ```

   If the build still uses the old sources, delete `build/_deps/vscp-*` or use
   **CMake: Delete Cache and Reconfigure** in VS Code.

If the new VSCP commit adds, renames, or removes source files that vscpd
compiles, update the source list in `CMakeLists.txt` to match.

## Binary TCP mode

Send `BINARY\r\n` to switch a connection to
[VSCP-GBP](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary).
The final text response is `+OK - Success.\r\n`; all subsequent traffic,
including event delivery, replies and receive-loop keepalives, is binary.
Authentication is preserved when switching modes.

Every binary frame has a two-byte **big-endian length prefix**, not including
the prefix itself. The enclosed frame follows VSCP-GBP; its first byte carries
the frame type and encryption selection. This TCP-specific length prefix is
required for variable-length commands/replies and applies in both directions.
Frames may be split across TCP reads or combined in one read.

Encryption codes 0 (none), 1 (AES-128), 2 (AES-192), and 3 (AES-256) are
supported using the daemon's configured `security.vscpkey`. Encrypted frames
use standard PKCS#7 padding and an appended 16-byte IV. This deliberately differs
from the helper library's zero padding, which cannot unambiguously delimit
variable-length encrypted commands. Replies and
asynchronous events use the encryption selection of the latest valid incoming
frame; the initial selection after `BINARY` is none. Use TLS to protect the
initial text exchange and configure a private shared key for frame encryption.
Invalid framing, encryption or CRC closes the connection.

Commands use the numeric codes and binary arguments/replies in the linked spec.
`OPEN` enables asynchronous events; `CLOSE` keeps events queued for `RETR`.
`USER`/`PASS` use the existing user and host authorization rules, with a
30-second timeout between binary `USER` and `PASS`. Reserved/user-defined
commands and `TEST` return `VSCP_ERROR_UNSUPPORTED`.
Binary command 24 (`TEXT`) receives a binary reply before switching back to text.
The maximum length-prefixed frame is 4096 bytes.

Configure with `-DVSCPD_BUILD_TESTS=ON` to enable the `binaryprotocol` CTest
regression test, covering event encoding, CRC validation, plaintext/AES
round trips across payload and padding lengths, fragmented/coalesced input,
mode transitions, permissions, event delivery and binary reply shapes.

## Windows service

The Windows daemon executable is `tcpip-vscpd.exe`. By default it runs under the
Windows Service Control Manager as the `tcpip-vscpd` service. Stop and system
shutdown requests shut down the daemon and its worker threads gracefully.

Run these commands from an elevated Command Prompt or PowerShell.

```bat
sc create tcpip-vscpd binPath= "\"C:\path\to\tcpip-vscpd.exe\" -c \"C:\path\to\vscpd.json\" -r \"C:\path\to\vscp\"" start= auto DisplayName= "VSCP TCP/IP Daemon"
sc start tcpip-vscpd
sc stop tcpip-vscpd
sc delete tcpip-vscpd
```

To run in console mode instead of service mode:

```bat
tcpip-vscpd.exe --console
```

`-s` also selects console mode. Without either option, launching the executable
outside the Service Control Manager fails explicitly. Use absolute configuration,
root-folder and log paths: a service does not inherit your interactive working
directory. The service account must have access to these paths.

## macOS service

On macOS, run the daemon as a `launchd` service.

Create `/Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist` with the following content:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>org.vscp.tcpip-vscpd</string>

	<key>ProgramArguments</key>
	<array>
		<string>/usr/local/sbin/tcpip-vscpd</string>
		<string>-c</string>
		<string>/usr/local/etc/vscp/vscpd.json</string>
	</array>

	<key>RunAtLoad</key>
	<true/>

	<key>KeepAlive</key>
	<true/>

	<key>StandardOutPath</key>
	<string>/var/log/tcpip-vscpd.log</string>

	<key>StandardErrorPath</key>
	<string>/var/log/tcpip-vscpd.err</string>
</dict>
</plist>
```

Load/start, stop/unload, and inspect status:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist
sudo launchctl kickstart -k system/org.vscp.tcpip-vscpd
sudo launchctl print system/org.vscp.tcpip-vscpd
sudo launchctl bootout system /Library/LaunchDaemons/org.vscp.tcpip-vscpd.plist
```

To run in console mode instead of launchd:

```bash
tcpip-vscpd -s
```

## Unix installation step

When you run CMake install on Unix, the startup script is installed as:

```text
/etc/init.d/tcpip-vscpd
```

Example:

```bash
cmake -S . -B build
cmake --build build
sudo cmake --install build
```
