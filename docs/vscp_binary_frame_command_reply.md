# vscp_writeCommandToFrame / vscp_writeReplyToFrame

These functions write VSCP binary protocol command and reply frames. They are used for the binary TCP/IP link protocol where commands and responses are exchanged as structured binary frames.

## Frame Formats

### Command Frame

Written by `vscp_writeCommandToFrame`:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Packet type (0xe0 = command, no encryption) |
| 1 | 2 | Command code (MSB first) |
| 3 | N | Optional argument data |
| 3+N | 2 | CRC-CCITT (MSB first) |

Total frame size: **5 + arg_len** bytes.

### Reply Frame

Written by `vscp_writeReplyToFrame`:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 1 | Packet type (0xf0 = response, no encryption) |
| 1 | 2 | Command code (MSB first) |
| 3 | 2 | Error code (MSB first) |
| 5 | N | Optional argument data |
| 5+N | 2 | CRC-CCITT (MSB first) |

Total frame size: **7 + arg_len** bytes.

## CRC Calculation

Both functions compute a **CRC-CCITT** checksum over the frame contents starting from byte 1 (after the packet type byte) through the end of the frame including the CRC byte positions (which are zero at the time of computation). The resulting 16-bit CRC is written in big-endian order as the last two bytes of the frame.

## vscp_writeCommandToFrame

```c
int vscp_writeCommandToFrame(uint8_t *frame,
                             size_t len,
                             uint16_t command,
                             const uint8_t *arg,
                             size_t arg_len);
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `frame` | Buffer that will receive the command frame. Must be at least `5 + arg_len` bytes. |
| `len` | Size of the buffer in bytes. |
| `command` | 16-bit command code to write to the frame. |
| `arg` | Pointer to optional argument data. Can be `NULL` if `arg_len` is 0. |
| `arg_len` | Length of argument data in bytes. Must be 0 if `arg` is `NULL`. |

### Return Value

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | `VSCP_ERROR_SUCCESS` | Frame written successfully. |
| 34 | `VSCP_ERROR_PARAMETER` | `frame` is `NULL`, or `arg` is `NULL` while `arg_len` > 0. |
| 43 | `VSCP_ERROR_BUFFER_TO_SMALL` | Buffer is too small for the frame. |

### Example

```c
uint8_t frame[64];
uint8_t arg[] = {0x01, 0x02, 0x03};

int rv = vscp_writeCommandToFrame(frame, sizeof(frame), 0x0010, arg, sizeof(arg));
if (VSCP_ERROR_SUCCESS == rv) {
    // frame now contains:
    //   [0]    = 0xe0  (command, no encryption)
    //   [1..2] = 0x00 0x10  (command code)
    //   [3..5] = 0x01 0x02 0x03  (argument data)
    //   [6..7] = CRC-CCITT
}
```

## vscp_writeReplyToFrame

```c
int vscp_writeReplyToFrame(uint8_t *frame,
                           size_t len,
                           uint16_t command,
                           uint16_t error,
                           const uint8_t *arg,
                           size_t arg_len);
```

### Parameters

| Parameter | Description |
|-----------|-------------|
| `frame` | Buffer that will receive the reply frame. Must be at least `7 + arg_len` bytes. |
| `len` | Size of the buffer in bytes. |
| `command` | 16-bit command code echoed back in the reply. |
| `error` | 16-bit error code (0 = success). |
| `arg` | Pointer to optional argument data. Can be `NULL` if `arg_len` is 0. |
| `arg_len` | Length of argument data in bytes. Must be 0 if `arg` is `NULL`. |

### Return Value

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | `VSCP_ERROR_SUCCESS` | Frame written successfully. |
| 34 | `VSCP_ERROR_PARAMETER` | `frame` is `NULL`, or `arg` is `NULL` while `arg_len` > 0. |
| 43 | `VSCP_ERROR_BUFFER_TO_SMALL` | Buffer is too small for the frame. |

### Example

```c
uint8_t frame[64];
uint8_t arg[] = {0xAA, 0xBB};

int rv = vscp_writeReplyToFrame(frame, sizeof(frame), 0x0010, 0x0000, arg, sizeof(arg));
if (VSCP_ERROR_SUCCESS == rv) {
    // frame now contains:
    //   [0]    = 0xf0  (response, no encryption)
    //   [1..2] = 0x00 0x10  (command code)
    //   [3..4] = 0x00 0x00  (error code = success)
    //   [5..6] = 0xAA 0xBB  (argument data)
    //   [7..8] = CRC-CCITT
}
```

## Related Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `VSCP_BINARY_PACKET_TYPE_COMMAND` | 0xe0 | Packet type for command frames |
| `VSCP_BINARY_PACKET_TYPE_RESPONSE` | 0xf0 | Packet type for response frames |
| `VSCP_ENCRYPTION_NONE` | 0x00 | No encryption |

## See Also

- `vscp_writeEventToFrame` — Write a VSCP event to a binary frame.
- `vscp_getEventFromFrame` — Read a VSCP event from a binary frame.
