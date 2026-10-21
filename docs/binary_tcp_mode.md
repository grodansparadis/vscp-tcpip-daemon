# Binary TCP mode

A TCP/IP Link connection starts in text mode. Send `BINARY` to switch the
connection to the
[VSCP General Binary Protocol (VSCP-GBP)](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary):

```text
BINARY
```

The final text response is `+OK - Success.`. After that, all traffic on the
connection is binary, including event delivery, replies and receive-loop
keepalives. If the client was logged in, it stays logged in after the switch.

## Framing

Every binary frame starts with a three-byte TCP header: a `0x55` sync byte,
followed by a big-endian word holding a 3-bit framing version and the 13-bit
frame length. The VSCP-GBP frame follows; its first byte holds the frame type
and the encryption selection.

The header is used in both directions. It is needed for variable-length
commands and replies, and it lets the receiver find the next frame after bad
data. Frames may be split across several TCP reads, or several frames may
arrive in one read.

The largest VSCP-GBP frame, not counting the header, is 4096 bytes.

See [Binary frame format](binary_frame_format.md) for the byte-level layout of
headers, commands, replies and events.

## Encryption

Encryption codes 0 (none), 1 (AES-128), 2 (AES-192) and 3 (AES-256) are
supported. The daemon uses the key configured in `security.vscpkey`.

Encrypted frames use standard PKCS#7 padding and an appended 16-byte IV. This
is deliberately different from the helper library's zero padding, which cannot
reliably mark where a variable-length encrypted command ends.

Replies and asynchronous events use the same encryption as the latest valid
frame received from the client. Right after `BINARY`, no encryption is used.

Frame encryption does not protect the text exchange that happens before
`BINARY`, including the login. Use [TLS](security_tls.md) to protect that part
of the session, and configure a private shared key for frame encryption.

## Invalid data

Invalid data does not close the connection. The daemon skips it and continues
with the next valid frame. See
[Errors and recovery](binary_frame_format.md#errors-and-recovery) for details.

## Commands

Binary commands use the numeric codes, arguments and replies defined in the
VSCP-GBP specification. The [command reference](tcpip_link_commands.md#binary-and-binary-command-equivalents)
lists the binary command codes supported by this daemon.

- `OPEN` turns on asynchronous event delivery. `CLOSE` turns it off; events
  then stay queued until the client fetches them with `RETR`.
- `USER` and `PASS` use the same user and host authorization rules as text
  mode. The client must send `PASS` within 30 seconds of `USER`.
- Reserved and user-defined commands, and `TEST`, return
  `VSCP_ERROR_UNSUPPORTED`.
- Command 24 (`TEXT`) sends a binary reply, then switches the connection back
  to text mode.

## Tests

Configure the build with `-DVSCPD_BUILD_TESTS=ON` to enable the
`binaryprotocol` CTest regression test. It covers event encoding, CRC
validation, plaintext and AES round trips across payload and padding lengths,
fragmented and combined input, mode transitions, permissions, event delivery,
binary reply shapes, and recovery from invalid data.

Two black-box suites test the protocol against a running daemon. On Linux and
macOS, they are also registered with CTest:

- **`binaryserver`:** a C++ program,
  [tests/binaryserver.cpp](../tests/binaryserver.cpp). It starts the built
  `vscpd` with a temporary configuration, a random system key and test users.
  It then checks login, rights, `SEND`/`RETR`, the receive loop, event frames,
  all encryption modes, resynchronization, and `TEXT`/`QUIT`.
- **`binaryserver_python`:** a Python `unittest` suite in
  [tests/binary_server/](../tests/binary_server/) with broader coverage. It is
  registered only when Python 3 and the `cryptography` and `pynacl` modules are
  found.

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
`VSCP_READER_PASSWORD` to a user that has only `receive-events` rights. This
enables the rights test. Set `VSCP_KEEP_TEMP=1` to keep the temporary daemon
folder, including `vscpd.log`, after a run.

The `tlsremote` CTest uses `vscpremotetcpif.cpp` and `vscpremotetcpif.h` from
the fetched VSCP source. It starts a TLS-enabled daemon with the certificates
in `install/certs/`, then checks explicit TLS mode, the `stcp://` endpoint
prefix, authenticated `NOOP` and `VERSION` commands, and that a plain TCP
connection to the TLS port is rejected.

See [Building from source](building.md) for general build and test
instructions.
