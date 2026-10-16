"""Minimal client for the VSCP TCP/IP daemon binary mode (VSCP-GBP).

Wire format of every binary frame:

    [0x55] [VER(3 bits) | LEN high 5 bits] [LEN low 8 bits] [VSCP-GBP frame]

The VSCP-GBP frame starts with a type/encryption byte and ends with a
CRC-CCITT computed over everything except the first byte. Encrypted frames
keep the first byte in clear text and append the 16-byte AES-CBC IV.
"""

import os
import socket
import struct
import time

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

SYNC_BYTE = 0x55
FRAMING_VERSION = 1
HEADER_SIZE = 3
MAX_FRAME_SIZE = 4096

TYPE_EVENT0 = 0x0
TYPE_EVENT1 = 0x1
TYPE_COMMAND = 0xE
TYPE_REPLY = 0xF

# Command codes.
NOOP = 0
QUIT = 1
USER = 2
PASS = 3
CHALLENGE = 4
SEND = 5
RETR = 6
RCVLOOP = 7
QUITLOOP = 8
CHKDATA = 9
CLRALL = 10
STAT = 11
INFO = 12
GETCHID = 13
SETGUID = 14
GETGUID = 15
VERSION = 16
SETFILTER = 17
SETMASK = 18
INTERFACE = 19
TEST = 20
WCYD = 21
SHUTDOWN = 22
RESTART = 23
TEXT = 24
ASYNC = 0xFFFF

# Error codes used by the server.
SUCCESS = 0
RCV_EMPTY = 19
PARAMETER = 34
INVALID_FRAME = 63
UNSUPPORTED = 71
NOT_AUTHORIZED = 74

DEFAULT_KEY = bytes.fromhex(
    "A4A86F7D7E119BA3F0CD06881E371B989B33B6D606A863B633EF529D64544F8E")

VSCP_HEADER16_FRAME_VERSION_UNIX_NS = 0x0100

_KEY_SIZES = {1: 16, 2: 24, 3: 32}


def crc_ccitt(data, crc=0xFFFF):
    """CRC-CCITT (polynomial 0x1021, initial 0xFFFF, not reflected)."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def with_crc(frame):
    """Return frame (without CRC) with its CRC appended."""
    return bytes(frame) + struct.pack(">H", crc_ccitt(frame[1:]))


def crc_ok(frame):
    return len(frame) >= 3 and crc_ccitt(frame[1:]) == 0


def header(length, version=FRAMING_VERSION):
    return bytes([SYNC_BYTE]) + struct.pack(">H", (version << 13) | length)


def encode(frame, encryption=0, key=DEFAULT_KEY, version=FRAMING_VERSION):
    """Encrypt (optionally) a complete VSCP-GBP frame and add the TCP header."""
    frame = bytes([(frame[0] & 0xF0) | encryption]) + bytes(frame[1:])
    if encryption:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        plain = padder.update(frame[1:]) + padder.finalize()
        cipher = Cipher(algorithms.AES(key[:_KEY_SIZES[encryption]]),
                        modes.CBC(iv)).encryptor()
        frame = frame[:1] + cipher.update(plain) + cipher.finalize() + iv
    if len(frame) > MAX_FRAME_SIZE:
        raise ValueError("frame too large")
    return header(len(frame), version) + frame


def decode(body, key=DEFAULT_KEY):
    """Decrypt a VSCP-GBP frame (without TCP header) and verify its CRC."""
    encryption = body[0] & 0x0F
    if encryption:
        iv = body[-16:]
        cipher = Cipher(algorithms.AES(key[:_KEY_SIZES[encryption]]),
                        modes.CBC(iv)).decryptor()
        plain = cipher.update(body[1:-16]) + cipher.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        body = body[:1] + unpadder.update(plain) + unpadder.finalize()
    if not crc_ok(body):
        raise ValueError("bad CRC")
    return body


def command_frame(code, arguments=b""):
    return with_crc(bytes([TYPE_COMMAND << 4]) + struct.pack(">H", code) +
                    bytes(arguments))


def event_frame(vscp_class, vscp_type, data=b"", guid=bytes(16),
                timestamp_ns=0, head=VSCP_HEADER16_FRAME_VERSION_UNIX_NS):
    """Build a type 1 event frame (Unix nanosecond timestamp)."""
    body = (bytes([TYPE_EVENT1 << 4]) + struct.pack(">HQ", head, timestamp_ns) +
            bytes(3) + struct.pack(">HH", vscp_class, vscp_type) + bytes(guid) +
            struct.pack(">H", len(data)) + bytes(data))
    return with_crc(body)


def event_payload(vscp_class, vscp_type, data=b"", guid=bytes(16),
                  timestamp_ns=0, head=VSCP_HEADER16_FRAME_VERSION_UNIX_NS):
    """SEND command arguments: an event frame without type byte and CRC."""
    return event_frame(vscp_class, vscp_type, data, guid, timestamp_ns,
                       head)[1:-2]


class Event:
    """Decoded event frame (type 0/1)."""

    def __init__(self, frame):
        self.frame = frame
        self.head, self.timestamp_ns = struct.unpack(">HQ", frame[1:11])
        self.vscp_class, self.vscp_type = struct.unpack(">HH", frame[14:18])
        self.guid = frame[18:34]
        size = struct.unpack(">H", frame[34:36])[0]
        self.data = frame[36:36 + size]

    @classmethod
    def from_body(cls, body):
        """Build from a RETR reply argument (frame without type and CRC)."""
        return cls(b"\x10" + bytes(body) + b"\x00\x00")


class Reply:
    def __init__(self, frame):
        self.frame = frame
        self.encryption = frame[0] & 0x0F
        self.command, self.error = struct.unpack(">HH", frame[1:5])
        self.arguments = frame[5:-2]

    def __repr__(self):
        return "Reply(command={}, error={}, args={})".format(
            self.command, self.error, self.arguments.hex())


class Client:
    """Blocking client for a VSCP daemon in binary mode."""

    def __init__(self, host, port, key=DEFAULT_KEY, encryption=0, timeout=5.0):
        self.key = key
        self.encryption = encryption
        self.timeout = timeout
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buffer = b""
        self.events = []
        self.welcome = self._read_text_until(b"+OK")

    # -- text mode ---------------------------------------------------------

    def _read_text_until(self, marker):
        deadline = time.monotonic() + self.timeout
        while marker not in self.buffer or \
                b"\r\n" not in self.buffer[self.buffer.index(marker):]:
            self._fill(deadline)
        end = self.buffer.index(marker)
        end = self.buffer.index(b"\r\n", end) + 2
        text, self.buffer = self.buffer[:end], self.buffer[end:]
        return text

    def text(self, line):
        """Send a text-mode command and return the response up to +OK/-OK."""
        self.sock.sendall(line.encode() + b"\r\n")
        deadline = time.monotonic() + self.timeout
        while True:
            hits = [self.buffer.find(m) for m in (b"+OK", b"-OK")]
            hits = [h for h in hits if h >= 0]
            if hits:
                return self._read_text_until(self.buffer[min(hits):min(hits) + 3])
            self._fill(deadline)

    def enter_binary(self):
        response = self.text("BINARY")
        if not response.startswith(b"+OK"):
            raise RuntimeError("BINARY rejected: {!r}".format(response))

    # -- raw I/O -----------------------------------------------------------

    def _fill(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("no data from server")
        self.sock.settimeout(remaining)
        try:
            chunk = self.sock.recv(65536)
        except socket.timeout as error:
            raise TimeoutError("no data from server") from error
        if not chunk:
            raise ConnectionError("connection closed by server")
        self.buffer += chunk

    def send_raw(self, data):
        self.sock.sendall(data)

    def send_frame(self, frame, encryption=None):
        enc = self.encryption if encryption is None else encryption
        self.sock.sendall(encode(frame, enc, self.key))

    def read_frame(self, timeout=None):
        """Read and decode the next binary frame from the server."""
        deadline = time.monotonic() + (timeout or self.timeout)
        while len(self.buffer) < HEADER_SIZE:
            self._fill(deadline)
        if self.buffer[0] != SYNC_BYTE:
            raise ValueError("missing sync byte: {}".format(self.buffer[:8].hex()))
        word = struct.unpack(">H", self.buffer[1:3])[0]
        if word >> 13 != FRAMING_VERSION:
            raise ValueError("unexpected framing version {}".format(word >> 13))
        length = word & 0x1FFF
        while len(self.buffer) < HEADER_SIZE + length:
            self._fill(deadline)
        body = self.buffer[HEADER_SIZE:HEADER_SIZE + length]
        self.buffer = self.buffer[HEADER_SIZE + length:]
        return decode(body, self.key)

    def read_reply(self, timeout=None):
        """Next reply frame; unsolicited events are queued in self.events."""
        while True:
            frame = self.read_frame(timeout)
            kind = frame[0] >> 4
            if kind == TYPE_REPLY:
                return Reply(frame)
            if kind in (TYPE_EVENT0, TYPE_EVENT1):
                self.events.append(Event(frame))
                continue
            raise ValueError("unexpected frame type {}".format(kind))

    def read_event(self, timeout=None):
        if self.events:
            return self.events.pop(0)
        while True:
            frame = self.read_frame(timeout)
            if frame[0] >> 4 in (TYPE_EVENT0, TYPE_EVENT1):
                return Event(frame)
            reply = Reply(frame)
            # Receive loop keep-alives are NOOP replies; skip them.
            if reply.command != NOOP:
                raise ValueError("unexpected reply {!r}".format(reply))

    def command(self, code, arguments=b"", encryption=None):
        self.send_frame(command_frame(code, arguments), encryption)
        return self.read_reply()

    def login(self, user, password):
        return self.command(USER, "{}:{}".format(user, password).encode())

    def is_closed(self, timeout=2.0):
        """True if the server closes the connection within timeout."""
        deadline = time.monotonic() + timeout
        try:
            while True:
                self._fill(deadline)
        except TimeoutError:
            return False
        except (ConnectionError, OSError):
            return True

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
