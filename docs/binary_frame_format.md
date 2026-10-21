# Binary frame format

The client and the daemon use the same layout for every binary message in
[VSCP-GBP](https://grodansparadis.github.io/vscp-doc-spec/#/vscp_over_binary):

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

## Command (client to daemon), type `0xE0`

| Byte   | Content                                  |
|--------|------------------------------------------|
| 0      | `0xE0` \| encryption                     |
| 1–2    | Command code                             |
| 3…     | Arguments (optional, command-specific)   |
| last 2 | CRC                                      |

For example, `NOOP` (command 0) is sent as `55 20 05  E0  00 00  1D 0F`.

## Reply (daemon to client), type `0xF0`

| Byte   | Content                                                            |
|--------|--------------------------------------------------------------------|
| 0      | `0xF0` \| encryption                                               |
| 1–2    | Command code being answered (for `INTERFACE`: command + subcommand) |
| 3–4    | Error code (`0` = success)                                         |
| 5…     | Reply arguments (optional)                                         |
| last 2 | CRC                                                                |

For example, a successful `NOOP` reply is `55 20 07  F0  00 00  00 00  84 C0`.

## Event (either direction), type `0x00` or `0x10`

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

## Encrypted frames (encryption 1–3)

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

## Errors and recovery

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
  treated as false and the search continues. Junk claiming a long length can't
  block the frames behind it.
- **Notification:** the first discard after a valid frame sends one reply with
  command `0xFFFF`, error `VSCP_ERROR_INVALID_FRAME` (63) and no arguments, so
  a client waiting on a corrupted command can resend it. No further error
  replies are sent until a valid frame has been received.

Frames may arrive split over several TCP reads or several in one read; the
header is what separates them.
