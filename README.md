# vscp-tcpip-daemon

![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Build VSCP library on Linux](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build.yml)
[![Build VSCP library on Windows](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-windows.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-windows.yml)
[![Build VSCP library on macOS](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-macos.yml/badge.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/actions/workflows/build-macos.yml)
[![Release](https://img.shields.io/github/release/grodansparadis/vscp-tcpip-daemon.svg)](https://github.com/grodansparadis/vscp-tcpip-daemon/releases)
[![Project Status: Active – The project has reached a stable, usable state and is being actively developed.](https://www.repostatus.org/badges/latest/active.svg)](https://www.repostatus.org/#active)

![VSCP Logo](https://github.com/grodansparadis/vscp-logo/blob/master/logo_100.png)


Full documentation is [here](https://grodansparadis.github.io/vscp-tcpip-daemon/#/)


A central VSCP daemon/server that exports a VSCP tcp/ip link interface and handles level I and level II drivers.

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

## Measurement command

Authenticated TCP clients with SEND permission can post a measurement using:

```text
measurement class,type,value,[unit],[index],[zone],[subzone],[guid],[timestamp_ns]
```

`class`, `type`, and the decimal numeric `value` are mandatory. Trailing optional
fields can be omitted; empty fields select their defaults. Unit, sensor index,
zone and subzone default to zero. GUID defaults to the connection's interface
GUID (also selected by `-`). The timestamp defaults to the current Unix time in
nanoseconds. An explicit timestamp is an unsigned 64-bit nanosecond count, or
`@` followed by a UTC ISO datetime such as
`@2026-10-16T08:00:00.123456789Z`. Fractional seconds may contain 1-9 digits.
The UTC suffix may be `Z`, `+00:00`, or omitted; other offsets are rejected.
Dates before the Unix epoch and timestamps beyond the unsigned 64-bit range
are rejected. Explicit zero is preserved.

The class selects the wire encoding, including the reserved X1-X4 variants:

| Classes | Value encoding | Metadata limits |
| --- | --- | --- |
| 10-14 (MEASUREMENT/X1-X4) | Signed integer for integer literals; IEEE-754 float32 for decimal/exponent notation | Unit 0-3, index 0-7; zone/subzone must be zero |
| 60-64 (MEASUREMENT64/X1-X4) | IEEE-754 float64 | Unit/index/zone/subzone must be zero |
| 65-69 (MEASUREZONE/X1-X4), 85-89 (SETVALUEZONE/X1-X4) | Normalized integer: signed mantissa of up to 3 bytes and decimal exponent -127 to 127 | Unit 0-3; index/zone/subzone 0-255 |
| 70-74 (MEASUREMENT32/X1-X4) | IEEE-754 float32 | Unit/index/zone/subzone must be zero |
| 1040 (MEASUREMENT_STR) | Original numeric text, zero terminated, at most 483 characters | Unit/index/zone/subzone 0-255 |
| 1060 (MEASUREMENT_FLOAT) | IEEE-754 float64 | Unit/index/zone/subzone 0-255 |

Integers in classes 10-14 must fit a signed 56-bit value. Floating point values
must be finite and fit the target precision; values that underflow to zero are
rejected. Normalized values must be exactly representable within the mantissa
and exponent limits. Class, type, and metadata accept decimal or `0x` hexadecimal
notation. Level I types are 0-255; Level II types are 0-65535.

```text
measurement 10,6,23.5,1
measurement 65,6,23.5,1,2,3,4
measurement 1060,6,23.5,1,2,3,4,,@2026-10-16T08:00:00Z
```

Invalid input returns a parameter error without sending an event. Both SEND
permission and the user's allowed class/type rules apply. Success queues an
event with the sender's client ID and updates receive statistics. This syntax
replaces the legacy `format,level,type,value,...` command.

Configure with `-DVSCPD_BUILD_TESTS=ON`, build `measurement_test`, then run
`ctest --test-dir build -R '^measurement$' --output-on-failure` for encoding,
timestamp, validation, permission and TCP-handler regression tests.

## Binary TCP mode

Send `BINARY\r\n` to switch a connection to
[VSCP-GBP](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary).
The final text response is `+OK - Success.\r\n`; all subsequent traffic,
including event delivery, replies and receive-loop keepalives, is binary.
Authentication is preserved when switching modes.

Every binary frame starts with a three-byte TCP header: a `0x55` sync byte,
then a big-endian word holding a 3-bit framing version and the 13-bit frame
length. The enclosed frame follows VSCP-GBP; its first byte carries the frame
type and encryption selection. The header is required for variable-length
commands/replies, lets the receiver find the next frame after bad data, and
applies in both directions. Frames may be split across TCP reads or combined
in one read.

Encryption codes 0 (none), 1 (AES-128), 2 (AES-192), and 3 (AES-256) are
supported using the daemon's configured `security.vscpkey`. Encrypted frames
use standard PKCS#7 padding and an appended 16-byte IV. This deliberately differs
from the helper library's zero padding, which cannot unambiguously delimit
variable-length encrypted commands. Replies and
asynchronous events use the encryption selection of the latest valid incoming
frame; the initial selection after `BINARY` is none. Use TLS to protect the
initial text exchange and configure a private shared key for frame encryption.
Invalid data does not close the connection; the daemon skips it and continues
with the next valid frame (see [Errors and recovery](#errors-and-recovery)).

Commands use the numeric codes and binary arguments/replies in the linked spec.
`OPEN` enables asynchronous events; `CLOSE` keeps events queued for `RETR`.
`USER`/`PASS` use the existing user and host authorization rules, with a
30-second timeout between binary `USER` and `PASS`. Reserved/user-defined
commands and `TEST` return `VSCP_ERROR_UNSUPPORTED`.
Binary command 24 (`TEXT`) receives a binary reply before switching back to text.
The maximum VSCP-GBP frame, excluding the header, is 4096 bytes.

Configure with `-DVSCPD_BUILD_TESTS=ON` to enable the `binaryprotocol` CTest
regression test, covering event encoding, CRC validation, plaintext/AES
round trips across payload and padding lengths, fragmented/coalesced input,
mode transitions, permissions, event delivery, binary reply shapes and
recovery from invalid data.

Two black-box suites also exercise the protocol against a running daemon.
On Linux and macOS they are registered with CTest as well:

- `binaryserver`: a C++ program
  ([tests/binaryserver.cpp](tests/binaryserver.cpp)). It starts the built
  `vscpd` with a temporary configuration, random system key and users, then
  checks login, rights, `SEND`/`RETR`, the receive loop, event frames, all
  encryption modes, resynchronisation and `TEXT`/`QUIT`.
- `binaryserver_python`: a Python `unittest` suite in
  [tests/binary_server/](tests/binary_server/) with broader coverage. It is
  registered only when Python 3 with the `cryptography` and `pynacl` modules
  is found.

```bash
cmake -S . -B build -DVSCPD_BUILD_TESTS=ON
cmake --build build --target binaryprotocol_test binaryserver_test tlsremote_test
ctest --test-dir build --output-on-failure

# Python suite: start a private daemon...
python3 tests/binary_server/test_binary_server.py --vscpd build/bin/vscpd
# ...or test a daemon that is already running
VSCP_HOST=127.0.0.1 VSCP_PORT=9598 VSCP_USER=admin VSCP_PASSWORD=secret \
  VSCP_KEY=<64 hex characters> python3 tests/binary_server/test_binary_server.py
```

When the Python suite tests a running daemon, set `VSCP_READER_USER` and
`VSCP_READER_PASSWORD` to a user that only has `receive-events` rights to
enable the rights test. Set `VSCP_KEEP_TEMP=1` to keep the temporary daemon
folder, including `vscpd.log`, after a run.

The `tlsremote` CTest uses `vscpremotetcpif.cpp` and
`vscpremotetcpif.h` from the fetched VSCP repository. It starts a TLS-enabled
daemon using the certificates in `install/certs/`, then verifies explicit TLS
mode, the `stcp://` endpoint prefix, authenticated `NOOP` and `VERSION`
commands, and rejection of a plain TCP connection to the TLS port.

### Binary frame format

The client and the daemon use the same layout for every binary message:

```
+------+--------------------+-----------+-------------------------------+
| 0x55 | VER(3) | LEN 12..8 | LEN 7..0  |  VSCP-GBP frame (LEN bytes)   |
+------+--------------------+-----------+-------------------------------+
```

- **Sync byte:** always `0x55`. It marks where a frame header starts.
- **Version and length:** the next two bytes are a big-endian word. The top 3
  bits are the framing version, currently `1`. The low 13 bits are `LEN`, the
  size of the VSCP-GBP frame that follows. `LEN` does not count the 3 header
  bytes and must be 5 to 4096. With version 1, the second header byte is
  `0x20 | (LEN >> 8)`.
- **Byte 0 of the frame:**
  - The high nibble is the frame type: `0`/`1` = event, `E` = command,
    `F` = reply.
  - The low nibble is the encryption: `0` none, `1` AES-128, `2` AES-192,
    `3` AES-256.
- **CRC (last 2 bytes):** CRC-CCITT (polynomial `0x1021`, start value
  `0xFFFF`, not reflected). It covers byte 1 up to, but not including, the CRC,
  and is stored big-endian.

All multi-byte numbers are big-endian. The layouts below are for unencrypted
frames.

#### Command (client to daemon), type `0xE0`

| Byte   | Content                                  |
|--------|------------------------------------------|
| 0      | `0xE0` \| encryption                     |
| 1–2    | Command code                             |
| 3…     | Arguments (optional, command-specific)   |
| last 2 | CRC                                      |

For example, `NOOP` (command 0) is sent as `55 20 05  E0  00 00  1D 0F`.

#### Reply (daemon to client), type `0xF0`

| Byte   | Content                                                          |
|--------|------------------------------------------------------------------|
| 0      | `0xF0` \| encryption                                             |
| 1–2    | Command code being answered (for `INTERFACE`: command + subcommand) |
| 3–4    | Error code (`0` = success)                                       |
| 5…     | Reply arguments (optional)                                       |
| last 2 | CRC                                                              |

For example, a successful `NOOP` reply is `55 20 07  F0  00 00  00 00  84 C0`.

#### Event (either direction), type `0x00` or `0x10`

An event frame is 38 bytes plus the data size.

| Byte   | Type 0 (`0x00`)                   | Type 1 (`0x10`)                            |
|--------|-----------------------------------|--------------------------------------------|
| 0      | `0x00` \| encryption              | `0x10` \| encryption                       |
| 1–2    | Head                              | Head                                       |
| 3–6    | Timestamp (µs, 32-bit)            | 64-bit nanosecond timestamp (bytes 3–10)   |
| 7–8    | Year                              | ↑                                          |
| 9–13   | Month, day, hour, minute, second  | 11–13 reserved                             |
| 14–15  | VSCP class                        | VSCP class                                 |
| 16–17  | VSCP type                         | VSCP type                                  |
| 18–33  | GUID (16 bytes)                   | GUID                                       |
| 34–35  | Data size *n* (at most 512)       | Data size *n*                              |
| 36…    | *n* data bytes                    | *n* data bytes                             |
| last 2 | CRC                               | CRC                                        |

Event confirmations:

- **Event the client sends:** the daemon answers with a 13-byte reply frame.
  It contains command `0xFFFF`, an error code, the event's head as 4 bytes and
  the event's CRC (2 bytes).
- **Event the daemon sends:** the client may confirm it with the same 13-byte
  reply shape.

#### Encrypted frames (encryption 1–3)

```
[55][VER|LEN][byte 0 in clear][AES-CBC(bytes 1..end incl. CRC, PKCS#7 padded)][16-byte IV]
```

- **What's encrypted:** byte 0 stays unencrypted. Everything after it is
  encrypted, including the CRC.
- **Padding:** PKCS#7 pads the encrypted part to a multiple of 16 bytes, so
  `LEN = 1 + 16·k + 16`.
- **IV:** a random 16-byte IV is appended after the encrypted data.
- **Key:** the daemon's `security.vscpkey`.
- **Encryption of replies and events:** the daemon uses the encryption setting
  from the client's most recent valid frame. Right after `BINARY`, there is no
  encryption.

#### Errors and recovery

Invalid data never closes the connection. The receiver searches for the next
valid frame instead:

- **Not a frame start:** bytes before the next `0x55` are discarded.
- **Bad header:** if the version is not `1`, `LEN` is outside 5–4096, or the
  frame's first byte has an unknown type or encryption code (or `LEN` doesn't
  fit the encrypted layout), the `0x55` is discarded and the search continues.
- **Bad frame:** if a complete frame fails decryption, padding or CRC, only its
  `0x55` is discarded and the search continues from the next byte, since the
  length itself may be wrong. A valid frame that follows is still handled.
- **Stalled frame:** if a frame stays incomplete for 2 seconds, its header is
  treated as false and the search continues. Junk claiming a long length
  can't block the frames behind it.
- **Notification:** the first discard after a valid frame sends one reply with
  command `0xFFFF`, error `VSCP_ERROR_INVALID_FRAME` (63) and no arguments, so
  a client waiting on a corrupted command can resend it. No further error
  replies are sent until a valid frame has been received.

Frames may arrive split over several TCP reads or several in one read; the
header is what separates them.

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

### Prebuilt Debian and Raspberry Pi packages

The [Debian & Raspberry Pi packages](.github/workflows/debian-packages.yml)
workflow builds `.deb` packages for Debian 12 (bookworm) and 13 (trixie), and
the matching Raspberry Pi OS releases:

| Target                  | Architecture | Hardware                          |
|-------------------------|--------------|-----------------------------------|
| Debian                  | `amd64`      | x86_64 PCs and servers            |
| Raspberry Pi OS 64-bit  | `arm64`      | Pi 3, 4, 5, 400, 500, Zero 2 W    |
| Raspberry Pi OS 32-bit  | `armhf`      | Pi 2, 3, 4, 5, Zero 2 W (ARMv7+)  |

The packages are available as workflow artifacts and are attached to the GitHub
release for `v*` tags. Install with:

```bash
sudo apt install ./vscp-tcpip-daemon_<version>_<codename>_<arch>.deb
```

To build the same package locally inside a container:

```bash
docker run --rm -v "$PWD:/src" -w /src debian:bookworm scripts/ci/build-deb.sh bookworm
```
