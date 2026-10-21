# VSCP TCP/IP Link Command Reference

This page documents the commands implemented by this VSCP TCP/IP daemon, including aliases, examples, and current limitations. Other VSCP servers and older releases may support different commands. The [VSCP Link specification](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_tcpiplink) describes the wider protocol.

For listener configuration, accounts, TLS, and Let's Encrypt certificates, see [Security and TLS](./security_tls.md). For device connections, see the [driver examples](./driver_interfaces.md#example-configurations).

## Connect and read replies

The default port is **9598**. Use the listener configured on your daemon; a TLS listener requires TLS from the start of the connection, not a `STARTTLS` command.

For a TLS server with a publicly trusted certificate, this Debian/Ubuntu example verifies both the certificate chain and the host name:

```bash
openssl s_client -connect vscp.example.com:9598 \
  -servername vscp.example.com -verify_hostname vscp.example.com \
  -CAfile /etc/ssl/certs/ca-certificates.crt \
  -verify_return_error -quiet -crlf
```

For a self-signed test certificate, replace `-CAfile` with the path to the trusted test certificate. Plain `telnet localhost 9598` is suitable only when the daemon is configured for unencrypted local TCP.

Protocol rules:

- Command names are case-insensitive. Use the complete command names shown below; do not rely on abbreviations other than the listed aliases.
- Each command is one line terminated by **CR/LF** (`\r\n`). The OpenSSL `-crlf` option supplies this when you press Enter.
- A text command line must be shorter than 2048 bytes, excluding CR/LF. An overlong command closes the connection after an error.
- A reply normally ends with `+OK` on success or `-OK` on failure. A description may follow ` - `.
- Commands that return data send the data lines before the final status line. `CHALLENGE` returns its value on the `+OK` line itself.
- In receive-loop mode, events arrive asynchronously. Stop the loop before using ordinary request/reply processing.
- Command examples below contain only what you type. Where replies are shown separately, they are illustrative; IDs, timestamps, versions, and statistics vary.

Here is a typical session. Replace the account name and password; the password sent with `PASS` is the actual password, **not** its stored hash:

```text
USER dashboard
PASS REPLACE_WITH_YOUR_PASSWORD
VERS
CHID
RCVLOOP
```

Read each reply before sending the next command. To finish:

```text
QUITLOOP
QUIT
```

Use a second authenticated connection to send events while the first receives them. The sender's own events are not normally echoed to the same channel.

## Command index and permissions

Log in before using operational commands. The rights below refer to the account's `privilege` configuration. An `admin` account has all rights; do not give normal applications administrative rights merely to make examples work.

| Command | Aliases | Purpose | Required account rights |
| :------ | :------ | :------ | :---------------------- |
| `NOOP` | None | Check that the connection responds. | No login required. |
| `USER` | None | Select an account. | No login required. |
| `PASS` | None | Authenticate the selected account. | A preceding `USER`. |
| `CHALLENGE` | None | Generate a session ID. | No login required. |
| `QUIT` | `EXIT` | Close the connection. | No login required. |
| `HELP` | None | Read built-in help. | No login required. |
| `VERS` | `VERSION` | Read the daemon version. | No login required. |
| `WCYD` | `WHATCANYOUDO` | Read the capability bitmap. | No login required. |
| `SEND` | None | Submit a VSCP event. | `send-events` and allowed class/type. |
| `MEASUREMENT` | `M` | Construct and submit a measurement. | `send-events` and allowed class/type. |
| `RETR` | `RETRIEVE` | Retrieve queued events. | `receive-events`. |
| `RCVLOOP` | `RECEIVELOOP` | Enable continuous event delivery. | `receive-events`. |
| `QUITLOOP` | `QUITRCVLOOP`, `QUITRECEIVELOOP` | Stop continuous delivery. | `receive-events`. |
| `CDTA` | `CHKDATA`, `CHECKDATA` | Count queued events. | Logged-in account. |
| `CLRA` | `CLRALL`, `CLEARALL` | Discard queued events. | Logged-in account. |
| `STAT` | None | Read channel statistics. | Logged-in account. |
| `INFO` | None | Read channel status. | Logged-in account. |
| `CHID` | `GETCHID` | Read the channel ID. | Logged-in account. |
| `GGID` | `GETGUID` | Read the channel GUID. | Logged-in account. |
| `SGID` | `SETGUID` | Request a channel GUID change; see current limitation below. | Set-GUID bit (`0x08000000`). |
| `SFLT` | `SETFILTER` | Set the channel's receive filter. | Set-filter bit (`0x04000000`). |
| `SMSK` | `SETMASK` | Set the channel's receive mask. | Set-filter bit (`0x04000000`). |
| `INTERFACE` | `CLIENT` | List interfaces; see limitations below. | `interface`. |
| `TEST` | None | Acknowledge a diagnostic request. | `test`. |
| `SHUTDOWN` | None | Stop the daemon process. | `shutdown`. |
| `RESTART` | None | Request a process restart. | `restart`. |
| `BINARY` | None | Switch this connection to VSCP-GBP frames. | No login required to switch; binary operations enforce their own rights. |

Named rights can be joined with `/`. For example, `user/0x04000000` adds filter-changing rights to a standard user, and `user/0x08000000` adds GUID-changing rights. The parser accepts these numeric bits; `setfilter` and `setguid` are not privilege names.

## Session and discovery commands

### NOOP

Check that the server is responsive without changing session state:

```text
NOOP
```

Reply: `+OK - Success.` An empty command line also receives a success reply.

### USER and PASS

Select an existing account, then authenticate:

```text
USER dashboard
PASS REPLACE_WITH_YOUR_PASSWORD
```

Successful replies:

```text
+OK - User name accepted, password please
+OK - Success.
```

The account is defined in `remoteuser`. The daemon checks its stored Argon2id hash and allowed remote addresses. A failed `PASS` closes the connection, so reconnect before retrying. To change accounts, open a new connection rather than sending another `USER` after login.

### CHALLENGE

Generate a new random session ID:

```text
CHALLENGE
```

The reply is `+OK - ` followed by a 64-character hexadecimal session ID. This implementation does **not** authenticate a client using that ID: use `USER` and `PASS` over TLS. No token argument is required.

### QUIT / EXIT

Close this connection without stopping the daemon:

```text
QUIT
```

The server sends `+OK - Connection closed by client.` and closes the connection. `EXIT` does the same.

With the current TLS connection-close handling, OpenSSL may then report `unexpected eof while reading`, even after a successful login and closing reply, because the connection ends without a TLS `close_notify`. Distinguish that final shutdown diagnostic from a failed certificate or host-name verification; keep `-verify_hostname` and `-verify_return_error` enabled. An EOF before the expected reply can indicate an interrupted exchange and should not be treated as success.

### HELP

List built-in help, or ask about a command:

```text
HELP
HELP SEND
HELP MEASUREMENT
```

Help text is followed by `+OK`. Built-in help contains some historical descriptions; the limitations on this page reflect the current implementation.

### VERS / VERSION

Read the version as three comma-separated numbers, followed by `+OK`:

```text
VERS
```

Reply format: `major,minor,patch`. The values follow the daemon's current release numbering.

### WCYD / WHATCANYOUDO

Read the server's 64-bit capability bitmap:

```text
WCYD
```

The data line has eight hexadecimal bytes separated by hyphens, most significant byte first: `XX-XX-XX-XX-XX-XX-XX-XX`. It is followed by `+OK`. Interpret bits using the [VSCP specification](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_tcpiplink); the bitmap is not a list of command names.

## Sending events

### SEND

Submit a fully specified VSCP event:

```text
SEND head,class,type,obid,datetime,timestamp,GUID,data0,data1,...
```

| Field | Meaning |
| :---- | :------ |
| `head` | Event header, including priority and frame-version flags. Usually start with `0`; the daemon sets the nanosecond frame version when `datetime` is empty. |
| `class`, `type` | VSCP class and type, normally given in decimal or with a `0x` hexadecimal prefix. |
| `obid` | Originating channel ID. Use `0` to let the daemon assign the sending channel ID. |
| `datetime` | Leave empty for the modern Unix-nanosecond timestamp format. Retained for older date/time-based senders. |
| `timestamp` | Unix time in nanoseconds when `datetime` is empty. Leave empty to use the current time. An explicit `0` is not the same as an empty field. |
| `GUID` | Source GUID in hexadecimal byte notation. Use an explicit GUID in new `SEND` integrations; do not assume this handler substitutes the channel GUID for `-`. |
| `data0...` | Event payload bytes, such as `0`, `35`, or `0x23`. The payload must match the event class/type. |

For example, send a Level I class 20, type 3 event with three data bytes:

```text
SEND 0,20,3,0,,,FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:01,0,1,35
```

The two empty fields after `obid` request the current timestamp. A success reply means the event was accepted into the daemon's queue, not that a device has acknowledged an action.

For a timestamp supplied by the application:

```text
SEND 0,20,3,0,,1792566000000000000,FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:01,0,1,35
```

The general event format allows up to 512 payload bytes, but the text-command line limit also applies. For large payloads, use a suitable binary client. Level I hardware may impose its own eight-byte payload limit.

### MEASUREMENT / M

Construct a measurement event without manually encoding its payload:

```text
MEASUREMENT class,type,value,[unit],[index],[zone],[subzone],[guid],[timestamp_ns]
```

The first three fields are required. Square brackets describe optional fields; do not type the brackets. Omitted trailing fields or empty optional fields use defaults: unit/index/zone/subzone `0`, the channel GUID, and the current timestamp. Use `-` for `guid` to select the channel GUID explicitly.

Examples:

```text
MEASUREMENT 10,6,23.5,1
M 65,6,23.5,1,2,3,4
MEASUREMENT 1060,6,23.5,1,2,3,4,,@2026-10-21T08:00:00Z
```

Type 6 is temperature; unit 1 is degrees Celsius for these measurement classes. The second example includes sensor index 2, zone 3, and subzone 4.

| Classes | Encoding and metadata |
| :------ | :-------------------- |
| 10-14 | Integer literals use signed integer coding; decimal/exponent values use float32. Unit 0-3, index 0-7; zone/subzone must be zero. |
| 60-64 | Float64. Unit, index, zone, and subzone must all be zero. |
| 65-69, 85-89 | Normalized integer with an exact signed mantissa of at most three bytes. Unit 0-3; index/zone/subzone 0-255. |
| 70-74 | Float32. Unit, index, zone, and subzone must all be zero. |
| 1040 | Zero-terminated numeric text, at most 483 characters. Unit/index/zone/subzone 0-255. |
| 1060 | Float64. Unit/index/zone/subzone 0-255. |

The ranges include the reserved X1-X4 variants. Class/type/metadata accept decimal or `0x` notation. Use a decimal numeric value, not a locale-specific comma. Non-finite, out-of-range, underflowing, or unrepresentable values are rejected rather than sent.

`timestamp_ns` accepts an unsigned 64-bit Unix nanosecond count or `@` followed by a UTC ISO date/time. Fractional seconds may have 1-9 digits; `Z`, `+00:00`, or no suffix denotes UTC. Other time-zone offsets and dates before 1970 are rejected. Unlike an empty timestamp, explicit zero is preserved.

For example:

```text
MEASUREMENT 1060,6,23.5,1,0,0,0,-,@2026-10-21T08:00:00.123456789Z
```

The old `format,level,type,value,...` measurement syntax is not supported by this daemon.

The measurement encoder and TCP command handler are covered by a regression
test. Configure with `-DVSCPD_BUILD_TESTS=ON`, build `measurement_test`, then
run:

```bash
cmake --build build --target measurement_test
ctest --test-dir build -R '^measurement$' --output-on-failure
```

## Receiving and managing queued events

### RETR / RETRIEVE

Retrieve one event, or up to a requested count, from this connection's queue:

```text
RETR
RETR 5
```

The default count is one. Use `RETR` when specifying a count: the current prefix-matching dispatcher also accepts `RETRIEVE`, but does not reliably preserve its count argument.

Each event is returned as a comma-separated data line, followed by the final status. Modern event lines use `head,class,type,obid,,timestamp_ns,GUID,data0,...`. If fewer events are available than requested, the server may return some events and then `-OK - No event(s) available` instead of a final success. Clients must preserve any events already received.

Retrieval removes events from the queue. Use `CDTA` first if you need to know how many are waiting, and stop `RCVLOOP` before polling with `RETR`.

### RCVLOOP / RECEIVELOOP

Start continuous event delivery:

```text
RCVLOOP
```

The server replies:

```text
+OK - Receive loop entered. QUITLOOP to terminate.
```

It then sends matching event lines as they become available. This is asynchronous delivery, not one `+OK` reply per event.

### QUITLOOP / QUITRCVLOOP / QUITRECEIVELOOP

Stop continuous delivery without closing the connection:

```text
QUITLOOP
```

Reply: `+OK - Quit receive loop.` Events already in flight can appear before that reply.

### CDTA / CHKDATA / CHECKDATA

Count events waiting for this connection:

```text
CDTA
```

Example reply:

```text
3
+OK - Success.
```

This does not remove the events.

### CLRA / CLRALL / CLEARALL

Discard all queued events for this connection:

```text
CLRA
```

Reply: `+OK - All events cleared.` Other clients' queues and device state are unaffected.

## Channel details and filters

### STAT

Read statistics for this channel, not totals for the whole daemon:

```text
STAT
```

The data line contains:

```text
bus_off,bus_warnings,overruns,receive_bytes,receive_frames,transmit_bytes,transmit_frames
```

A `+OK` line follows. Receive counters describe events submitted by this client to the daemon; transmit counters describe events delivered toward the client. An idle channel can return all zeroes.

### INFO

Read channel status and its last recorded error:

```text
INFO
```

Data format:

```text
channel_status,last_error_code,last_error_subcode,"last_error_text"
```

The data line is followed by `+OK`. This reports channel state, not a hardware self-test.

### CHID / GETCHID

Read the numeric ID assigned to this connection:

```text
CHID
```

The response is a decimal ID on one line followed by `+OK`. IDs are assigned at runtime; do not assume that the same reconnecting client will keep its ID.

### GGID / GETGUID

Read this connection's interface GUID:

```text
GGID
```

The response is a hexadecimal GUID on one line followed by `+OK`.

### SGID / SETGUID

The protocol command requests a change to this connection's interface GUID:

```text
SGID FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:02
```

**Current text-handler limitation:** the daemon returns success but updates a temporary GUID copy, so the channel GUID reported by `GGID` does not change. Do not rely on text `SGID` or `SETGUID` to select a measurement source. Supply the GUID explicitly to `SEND` or `MEASUREMENT`, or use binary command 14, which updates the channel through its setter.

The requested scope is the connection's GUID, not the daemon's global GUID or another driver's configured GUID.

### SFLT / SETFILTER and SMSK / SETMASK

Set the receive filter and the bits that must match it:

```text
SFLT priority,class,type,GUID
SMSK priority-mask,class-mask,type-mask,GUID-mask
```

A mask bit of zero means "ignore this bit"; a mask bit of one means "this bit must equal the filter value". Both commands return a success reply.

To receive class 10, type 6 events from any source and at any priority:

```text
SFLT 0,10,6,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
SMSK 0,65535,65535,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
```

To stop filtering by any field:

```text
SFLT 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
SMSK 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
```

Filters apply to subsequent event delivery; use `CLRA` if you also want to discard events already queued under the previous filter. The account's initial receive filter is copied to the channel at login. Allowing an account to change filters lets it change that channel filter; do not treat it as a separate immutable restriction.

## Interfaces and administration

### INTERFACE / CLIENT

List connected interfaces, drivers, and clients:

```text
INTERFACE LIST
```

`INTERFACE`, `CLIENT`, and `CLIENT LIST` also list them. Each data line has this form, followed by a final `+OK` after all rows:

```text
client_id,interface_type,GUID,name | Started at timestamp
```

There is no separate count line in the text implementation. Use `CHID` to identify your own connection in the list.

The dispatcher also recognizes the following historical subcommands, but their text handlers are **not implemented**:

| Example | Current result |
| :------ | :------------- |
| `INTERFACE UNIQUE FF:FF:FF:FF:FF:FF:FF:F5:01:00:00:00:00:00:00:00` | Returns `-OK - Interface not found.` It does not acquire exclusive access. |
| `INTERFACE NORMAL 1` | No operation and no reply. Do not wait indefinitely for a status line. |
| `INTERFACE CLOSE 1` | No operation and no reply. It does not close that interface. |

The same limitation applies with `CLIENT` instead of `INTERFACE`. Do not use these subcommands to control drivers; configure and restart the daemon through its service manager instead.

### TEST

```text
TEST
```

The current text handler returns `+OK - Success.` It does not run a diagnostic sequence or test connected hardware.

### SHUTDOWN

**Disruptive operation:** stops the daemon process and disconnects clients and drivers.

```text
SHUTDOWN
```

The daemon sends a closing reply and requests process termination (`SIGUSR1` on Unix). A service manager may restart it according to the service policy. For planned maintenance, use the service manager to stop it deliberately.

### RESTART

**Disruptive operation:**

```text
RESTART
```

The daemon acknowledges the command, then sends `SIGUSR2` to its process on Unix. This is not a portable in-process reload: on Windows the handler requests shutdown, and a supervisor must arrange any subsequent restart. For a predictable Linux service restart, use:

```bash
sudo systemctl restart vscpd
```

## BINARY and binary command equivalents

### BINARY

Switch this connection from text commands to the [VSCP General Binary Protocol (VSCP-GBP)](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary):

```text
BINARY
```

The final text response is `+OK - Success.` Authentication is preserved. From then on, every command and response must use binary framing; typing `NOOP` as text no longer works. Binary command 24 (`TEXT`) sends its binary acknowledgement before switching back to text.

Every frame has a three-byte TCP prefix: `0x55`, followed by a big-endian word containing framing version 1 in its upper three bits and frame length in the lower 13 bits. The VSCP-GBP frame follows, including its type/encryption byte and CRC. Its maximum size is 4096 bytes, excluding the TCP prefix. Do not omit this prefix.

For an overview of binary mode, encryption and its tests, see
[Binary TCP mode](binary_tcp_mode.md). For the full frame layout,
command/reply/event fields and error recovery behavior, see
[Binary frame format](binary_frame_format.md).

For example, an unencrypted binary `NOOP` command, including prefix and CRC, is:

```text
55 20 05 E0 00 00 1D 0F
```

These are hexadecimal bytes to send with a binary-capable client, **not** a line of text. TLS can protect unencrypted VSCP-GBP frames. Optional frame-level AES encryption does not replace TLS for the initial text login.

### Binary command index

The examples below show the command number and its **argument bytes**, not a complete wire frame. Multi-byte numbers are big-endian. Empty arguments mean zero bytes; GUIDs are 16 raw bytes, not colon-separated text.

| Code | Command | Example argument bytes or value | Behaviour |
| ---: | :------ | :------------------------------ | :-------- |
| 0 | `NOOP` | Empty. | Success reply. |
| 1 | `QUIT` | Empty. | Reply, then disconnect. |
| 2 | `USER` | ASCII `dashboard`, or `dashboard:password`. | Select a user; the combined form also attempts login. |
| 3 | `PASS` | ASCII password. | Authenticate; complete a separate `USER`/`PASS` exchange within 30 seconds. |
| 4 | `CHALLENGE` | Empty. | Returns a 32-character ASCII hex session ID; unlike text `CHALLENGE`, it uses 16 random bytes. |
| 5 | `SEND` | Encoded VSCP-GBP event body. | Queues the event. Use a VSCP encoder; omit the outer frame type and CRC from the argument body. |
| 6 | `RETR` | `00 02` (two events), or empty (one). | One event body per successful reply; an empty queue returns a receive-empty error. Not supported during receive-loop mode. |
| 7 | `RCVLOOP` / `OPEN` | Empty. | Enables asynchronous event frames. |
| 8 | `QUITLOOP` / `CLOSE` | Empty. | Stops asynchronous delivery; the connection stays open. |
| 9 | `CDTA` | Empty. | Returns a 32-bit queue count; returns zero during receive-loop mode. |
| 10 | `CLRA` | Empty. | Clears the queue only outside receive-loop mode. |
| 11 | `STAT` | Empty. | Returns eight 32-bit fields: three reserved zeroes, received bytes/frames, transmitted bytes/frames, and overruns. This differs from text `STAT`. |
| 12 | `INFO` | Empty. | Three 32-bit status/error fields and a zero-terminated error string of at most 79 characters. |
| 13 | `CHID` | Empty. | Returns the channel ID as a 32-bit value. |
| 14 | `SGID` | Sixteen GUID bytes. | Sets the channel GUID. |
| 15 | `GGID` | Empty. | Returns sixteen GUID bytes. |
| 16 | `VERS` | Empty. | Three 16-bit version numbers followed by a reserved 32-bit zero. |
| 17 | `SFLT` | 21 zero bytes to set a zero-valued filter. | Filter: priority byte, 16-bit class, 16-bit type, 16-byte GUID. An optional second 21-byte block sets the mask in the same command. |
| 18 | `SMSK` | 21 zero bytes to ignore all filter fields. | Sets the mask using the same 21-byte layout. |
| 19 | `INTERFACE` | `00` (count), `01 00 00` (describe index 0), `02 00 00` (close index 0), `03 00 00` (open index 0). | Uses zero-based list indices, not text `CHID` values. The reply command number is 19 plus the selector. |
| 20 | `TEST` | Empty. | Returns `VSCP_ERROR_UNSUPPORTED`; unlike text `TEST`, it is not a success-only stub. |
| 21 | `WCYD` | Empty, or eight bytes. | Returns eight capability bytes, most significant byte first. The optional argument is currently ignored. |
| 22 | `SHUTDOWN` | Empty. | Disruptive; replies, then requests process termination. |
| 23 | `RESTART` | Empty. | Disruptive; same process-control limitations as the text command. |
| 24 | `TEXT` | Empty. | Binary reply, then switch to text. |

Use a valid binary encoder for each example. `USER` and `PASS` accept at most 64 bytes per credential in binary mode. There is no separate binary `MEASUREMENT` command; construct a measurement event and send it. Reserved or user-defined command codes return an unsupported error.

The daemon also accepts standalone event frames, which are not command 5 frames. For complete layouts, CRC/encryption rules, and event acknowledgements, see the [binary protocol specification](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary).

## Unsupported legacy commands and errors

Do not infer support solely from older VSCP documentation or the built-in help text:

- `+`, `+n`, and `++` command-history shortcuts are not active in the current text parser.
- `REMOTE`, remote-variable commands, and table commands are not dispatched by this daemon.
- There is no text `STARTTLS` or `TEXT` command. Configure TLS on the listener; return from binary mode using binary command 24.
- The text `INTERFACE UNIQUE`, `NORMAL`, and `CLOSE` limitations are described above.

Examples of commands that are **not supported**, rather than actions to use in a working session:

```text
+
REMOTE
VARIABLE READ example
TABLE LIST
STARTTLS
```

An unrecognized command normally receives `-OK - Unknown command`. Other common text failures include:

| Reply | Meaning |
| :---- | :------ |
| `-OK - Need to log in to perform this command.` | Authenticate first. |
| `-OK - User does not have rights to perform this operation.` | The account lacks the required right. |
| `-OK - Invalid parameter or format` | Check the command's field count, values, and supported syntax. |
| `-OK - Invalid username or password.` | Authentication failed; reconnect before retrying. |
| `-OK - Invalid or unknown peer.` | The account does not allow the client's remote address. |
| `-OK - No event(s) available` | The receive queue is empty or has fewer events than requested. |
| `-OK - Buffer Full` | The daemon could not queue the event; do not assume it was sent. |

Treat `-OK` as an error even if the connection remains open. Use timeouts, preserve any data received before a failure, and reconnect if the server closes the connection.

[filename](./bottom_copyright.md ':include')
