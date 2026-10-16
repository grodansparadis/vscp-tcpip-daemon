#!/usr/bin/env python3
"""Black-box test suite for the VSCP TCP/IP daemon binary protocol.

Run against a daemon started by the suite itself (recommended):

    python3 tests/binary_server/test_binary_server.py --vscpd build/bin/vscpd

or against an already running server:

    VSCP_HOST=127.0.0.1 VSCP_PORT=9598 VSCP_USER=admin VSCP_PASSWORD=secret \\
    VSCP_KEY=<64 hex chars> python3 tests/binary_server/test_binary_server.py

Optional: VSCP_READER_USER / VSCP_READER_PASSWORD for a user that only has
the "receive-events" right (enables the authorization tests).

Requires the Python packages "cryptography" and, when the suite starts the
daemon itself, "pynacl" (to create the libsodium password hash).
"""

import argparse
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import vscp_binary as vb  # noqa: E402

TEST_CLASS = 20  # CLASS1.INFORMATION
SERVER = {}


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_daemon(executable):
    import nacl.pwhash

    folder = tempfile.mkdtemp(prefix="vscpd-binary-test-")
    port = _free_port()
    key = os.urandom(32)
    password = uuid.uuid4().hex
    reader_password = uuid.uuid4().hex

    def user(name, secret, privilege):
        return {"username": name,
                "password": nacl.pwhash.str(secret.encode()).decode(),
                "privilege": privilege,
                "allowed_remotes": "",
                "allowed_events": "*:*"}

    config = {
        "guid": "FF:FF:FF:FF:FF:FF:FF:F5:00:00:00:00:00:00:00:01",
        "logging": {"file-enable-log": False, "syslog-enable-log": False,
                    "udp-enable-log": False, "console-enable-log": True,
                    "console-log-level": "info"},
        "security": {"vscpkey": key.hex().upper()},
        "tcpip": {"interface-address": "tcp://127.0.0.1:{}".format(port)},
        "remoteuser": [user("admin", password, "admin"),
                       user("reader", reader_password, "receive-events")],
    }
    config_path = os.path.join(folder, "vscpd.json")
    with open(config_path, "w") as handle:
        json.dump(config, handle)
    log = open(os.path.join(folder, "vscpd.log"), "w")
    process = subprocess.Popen([executable, "-s", "-r", folder, "-c", config_path],
                               stdout=log, stderr=subprocess.STDOUT, cwd=folder)
    deadline = time.monotonic() + 15
    while True:
        if process.poll() is not None:
            raise RuntimeError("vscpd exited early, see " + log.name)
        try:
            vb.Client("127.0.0.1", port, key, timeout=1).close()
            break
        except OSError:
            if time.monotonic() > deadline:
                process.kill()
                raise RuntimeError("vscpd did not start, see " + log.name)
            time.sleep(0.1)
    SERVER.update(host="127.0.0.1", port=port, key=key, user="admin",
                  password=password, reader="reader",
                  reader_password=reader_password, process=process,
                  folder=folder, log=log)


def stop_daemon():
    process = SERVER.get("process")
    if not process:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    SERVER["log"].close()
    if process.returncode not in (0, -15):
        with open(SERVER["log"].name) as handle:
            sys.stderr.write(handle.read()[-4000:])
    if not os.environ.get("VSCP_KEEP_TEMP"):
        shutil.rmtree(SERVER["folder"], ignore_errors=True)


def configure_external():
    SERVER.update(
        host=os.environ.get("VSCP_HOST", "127.0.0.1"),
        port=int(os.environ.get("VSCP_PORT", "9598")),
        key=bytes.fromhex(os.environ.get("VSCP_KEY", vb.DEFAULT_KEY.hex())),
        user=os.environ.get("VSCP_USER", "admin"),
        password=os.environ.get("VSCP_PASSWORD", "secret"),
        reader=os.environ.get("VSCP_READER_USER"),
        reader_password=os.environ.get("VSCP_READER_PASSWORD"))


class BinaryServerTest(unittest.TestCase):

    def setUp(self):
        self.clients = []

    def tearDown(self):
        for client in self.clients:
            client.close()

    # -- helpers -----------------------------------------------------------

    def connect(self, encryption=0, login=True, user=None, password=None):
        client = vb.Client(SERVER["host"], SERVER["port"], SERVER["key"],
                           encryption)
        self.clients.append(client)
        client.enter_binary()
        if login:
            reply = client.login(user or SERVER["user"],
                                 password or SERVER["password"])
            self.assertOk(reply, vb.USER)
        return client

    def assertOk(self, reply, command):
        self.assertEqual(reply.command, command, reply)
        self.assertEqual(reply.error, vb.SUCCESS, reply)

    def assertError(self, reply, command, error):
        self.assertEqual(reply.command, command, reply)
        self.assertEqual(reply.error, error, reply)

    def drain(self, client):
        """Empty the client's server-side queue."""
        self.assertOk(client.command(vb.CLRALL), vb.CLRALL)

    def unique_type(self):
        return struct.unpack(">H", os.urandom(2))[0] & 0xFF

    def retr_matching(self, client, vscp_type, timeout=3.0):
        """RETR until an event with the test class and type arrives."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            reply = client.command(vb.RETR)
            if reply.error == vb.RCV_EMPTY:
                time.sleep(0.05)
                continue
            self.assertOk(reply, vb.RETR)
            event = vb.Event.from_body(reply.arguments)
            if (event.vscp_class, event.vscp_type) == (TEST_CLASS, vscp_type):
                return event
        self.fail("event {}:{} not received".format(TEST_CLASS, vscp_type))

    # -- connection and mode switching -------------------------------------

    def test_welcome_and_binary_switch(self):
        client = vb.Client(SERVER["host"], SERVER["port"], SERVER["key"])
        self.clients.append(client)
        self.assertIn(b"+OK", client.welcome)
        self.assertNotIn(b"\x00", client.welcome)
        self.assertTrue(client.welcome.endswith(b"+OK - Success.\r\n"))
        client.enter_binary()
        self.assertOk(client.command(vb.NOOP), vb.NOOP)

    def test_noop_in_every_encryption_mode(self):
        client = self.connect(login=False)
        for encryption in range(4):
            reply = client.command(vb.NOOP, encryption=encryption)
            self.assertOk(reply, vb.NOOP)
            self.assertEqual(reply.encryption, encryption)

    def test_text_mode_round_trip(self):
        client = self.connect()
        self.assertOk(client.command(vb.TEXT), vb.TEXT)
        self.assertTrue(client.text("NOOP").startswith(b"+OK"))
        client.enter_binary()
        self.assertOk(client.command(vb.GETCHID), vb.GETCHID)

    def test_quit_closes_connection(self):
        client = self.connect(login=False)
        self.assertOk(client.command(vb.QUIT), vb.QUIT)
        self.assertTrue(client.is_closed())

    # -- public commands ---------------------------------------------------

    def test_version(self):
        reply = self.connect(login=False, encryption=3).command(vb.VERSION)
        self.assertOk(reply, vb.VERSION)
        self.assertEqual(len(reply.arguments), 10)

    def test_capabilities(self):
        reply = self.connect(login=False).command(vb.WCYD)
        self.assertOk(reply, vb.WCYD)
        self.assertEqual(len(reply.arguments), 8)

    def test_challenge(self):
        reply = self.connect(login=False).command(vb.CHALLENGE)
        self.assertOk(reply, vb.CHALLENGE)
        self.assertRegex(reply.arguments.decode(), r"^[0-9a-f]{32}$")

    # -- authentication ----------------------------------------------------

    def test_commands_require_login(self):
        client = self.connect(login=False)
        for code in (vb.GETCHID, vb.RCVLOOP, vb.STAT, vb.CHKDATA):
            self.assertError(client.command(code), code, vb.NOT_AUTHORIZED)
        self.assertFalse(client.is_closed(0.3))

    def test_login_user_then_password(self):
        client = self.connect(login=False, encryption=2)
        self.assertOk(client.command(vb.USER, SERVER["user"].encode()), vb.USER)
        self.assertOk(client.command(vb.PASS, SERVER["password"].encode()),
                      vb.PASS)
        self.assertOk(client.command(vb.GETCHID), vb.GETCHID)

    def test_wrong_password_closes_connection(self):
        client = self.connect(login=False)
        reply = client.login(SERVER["user"], "not-the-password")
        self.assertError(reply, vb.USER, vb.NOT_AUTHORIZED)
        self.assertTrue(client.is_closed())

    def test_password_without_user_is_rejected(self):
        client = self.connect(login=False)
        reply = client.command(vb.PASS, b"whatever")
        self.assertError(reply, vb.PASS, vb.NOT_AUTHORIZED)

    def test_rights_are_enforced(self):
        if not SERVER.get("reader"):
            self.skipTest("VSCP_READER_USER not configured")
        client = self.connect(user=SERVER["reader"],
                              password=SERVER["reader_password"])
        payload = vb.event_payload(TEST_CLASS, 1)
        self.assertError(client.command(vb.SEND, payload), vb.SEND,
                         vb.NOT_AUTHORIZED)
        self.assertError(client.command(vb.SHUTDOWN), vb.SHUTDOWN,
                         vb.NOT_AUTHORIZED)
        self.assertOk(client.command(vb.CHKDATA), vb.CHKDATA)

    # -- informational commands --------------------------------------------

    def test_information_commands(self):
        client = self.connect(encryption=1)
        expected = {vb.CHKDATA: 4, vb.STAT: 32, vb.GETCHID: 4, vb.GETGUID: 16}
        for code, size in expected.items():
            reply = client.command(code)
            self.assertOk(reply, code)
            self.assertEqual(len(reply.arguments), size, reply)
        reply = client.command(vb.INFO)
        self.assertOk(reply, vb.INFO)
        self.assertGreaterEqual(len(reply.arguments), 13)
        self.assertEqual(reply.arguments[-1], 0)

    def test_set_and_get_guid(self):
        client = self.connect()
        guid = bytes(range(0xA0, 0xB0))
        self.assertOk(client.command(vb.SETGUID, guid), vb.SETGUID)
        reply = client.command(vb.GETGUID)
        self.assertOk(reply, vb.GETGUID)
        self.assertEqual(reply.arguments, guid)

    def test_interface_list(self):
        client = self.connect()
        reply = client.command(vb.INTERFACE, b"\x00")
        self.assertOk(reply, vb.INTERFACE)
        count = struct.unpack(">H", reply.arguments)[0]
        self.assertGreaterEqual(count, 1)
        reply = client.command(vb.INTERFACE, b"\x01\x00\x00")
        self.assertOk(reply, vb.INTERFACE + 1)
        self.assertEqual(len(reply.arguments), 82)

    def test_parameter_errors(self):
        client = self.connect()
        self.assertError(client.command(vb.NOOP, b"\x00"), vb.NOOP, vb.PARAMETER)
        self.assertError(client.command(vb.SETGUID, b"\x00" * 15), vb.SETGUID,
                         vb.PARAMETER)
        self.assertError(client.command(vb.SETFILTER, b"\x00" * 3),
                         vb.SETFILTER, vb.PARAMETER)
        self.assertError(client.command(vb.INTERFACE, b"\x04"), vb.INTERFACE,
                         vb.PARAMETER)

    def test_unknown_command(self):
        client = self.connect()
        self.assertError(client.command(200), 200, vb.UNSUPPORTED)

    # -- events ------------------------------------------------------------

    def test_send_and_retr(self):
        sender, receiver = self.connect(encryption=3), self.connect(encryption=1)
        self.drain(receiver)
        vscp_type, data = self.unique_type(), b"\x01\x02\x03"
        reply = sender.command(vb.SEND,
                               vb.event_payload(TEST_CLASS, vscp_type, data))
        self.assertOk(reply, vb.SEND)
        event = self.retr_matching(receiver, vscp_type)
        self.assertEqual(event.data, data)

    def test_event_frame_is_confirmed(self):
        sender, receiver = self.connect(encryption=2), self.connect()
        self.drain(receiver)
        vscp_type = self.unique_type()
        frame = vb.event_frame(TEST_CLASS, vscp_type, b"\xAA")
        sender.send_frame(frame)
        reply = sender.read_reply()
        self.assertOk(reply, vb.ASYNC)
        head = struct.unpack(">H", frame[1:3])[0]
        self.assertEqual(reply.arguments, struct.pack(">I", head) + frame[-2:])
        self.assertEqual(self.retr_matching(receiver, vscp_type).data, b"\xAA")

    def test_events_are_not_echoed_to_sender(self):
        client = self.connect()
        self.drain(client)
        vscp_type = self.unique_type()
        self.assertOk(client.command(
            vb.SEND, vb.event_payload(TEST_CLASS, vscp_type)), vb.SEND)
        time.sleep(0.3)
        while True:
            reply = client.command(vb.RETR)
            if reply.error == vb.RCV_EMPTY:
                break
            event = vb.Event.from_body(reply.arguments)
            self.assertNotEqual((event.vscp_class, event.vscp_type),
                                (TEST_CLASS, vscp_type))

    def test_receive_loop_delivers_events(self):
        sender, receiver = self.connect(), self.connect(encryption=3)
        self.drain(receiver)
        self.assertOk(receiver.command(vb.RCVLOOP), vb.RCVLOOP)
        self.assertError(receiver.command(vb.RETR), vb.RETR, vb.UNSUPPORTED)
        vscp_type, data = self.unique_type(), bytes(range(8))
        self.assertOk(sender.command(
            vb.SEND, vb.event_payload(TEST_CLASS, vscp_type, data,
                                      timestamp_ns=123456789)), vb.SEND)
        deadline = time.monotonic() + 3
        while True:
            self.assertLess(time.monotonic(), deadline, "event not delivered")
            event = receiver.read_event()
            if (event.vscp_class, event.vscp_type) == (TEST_CLASS, vscp_type):
                break
        self.assertEqual(event.data, data)
        self.assertEqual(event.frame[0], 0x13)
        self.assertEqual(event.timestamp_ns, 123456789)
        self.assertOk(receiver.command(vb.QUITLOOP), vb.QUITLOOP)

    def test_retr_count_and_empty_queue(self):
        sender, receiver = self.connect(), self.connect()
        self.drain(receiver)
        self.assertError(receiver.command(vb.RETR), vb.RETR, vb.RCV_EMPTY)
        vscp_type = self.unique_type()
        for index in range(3):
            self.assertOk(sender.command(vb.SEND, vb.event_payload(
                TEST_CLASS, vscp_type, bytes([index]))), vb.SEND)
        deadline = time.monotonic() + 3
        while True:
            reply = receiver.command(vb.CHKDATA)
            if struct.unpack(">I", reply.arguments)[0] >= 3:
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        receiver.send_frame(vb.command_frame(vb.RETR, b"\x00\x03"))
        data = []
        for _ in range(3):
            reply = receiver.read_reply()
            self.assertOk(reply, vb.RETR)
            event = vb.Event.from_body(reply.arguments)
            if event.vscp_type == vscp_type:
                data.append(event.data)
        self.assertEqual(data, [b"\x00", b"\x01", b"\x02"])

    def test_filter_blocks_other_events(self):
        sender, receiver = self.connect(), self.connect()
        filter_args = bytes([0]) + struct.pack(">HH", TEST_CLASS, 0) + bytes(16)
        mask_args = bytes([0]) + struct.pack(">HH", 0xFFFF, 0) + bytes(16)
        self.assertOk(receiver.command(vb.SETFILTER, filter_args + mask_args),
                      vb.SETFILTER)
        self.drain(receiver)
        vscp_type = self.unique_type()
        self.assertOk(sender.command(vb.SEND, vb.event_payload(
            TEST_CLASS + 1, vscp_type)), vb.SEND)
        self.assertOk(sender.command(vb.SEND, vb.event_payload(
            TEST_CLASS, vscp_type)), vb.SEND)
        event = self.retr_matching(receiver, vscp_type)
        self.assertEqual(event.vscp_class, TEST_CLASS)
        time.sleep(0.2)
        while True:
            reply = receiver.command(vb.RETR)
            if reply.error == vb.RCV_EMPTY:
                break
            self.assertEqual(vb.Event.from_body(reply.arguments).vscp_class,
                             TEST_CLASS)

    def test_maximum_event_size(self):
        sender, receiver = self.connect(encryption=3), self.connect(encryption=3)
        self.drain(receiver)
        vscp_type, data = self.unique_type(), os.urandom(512)
        self.assertOk(sender.command(vb.SEND, vb.event_payload(
            TEST_CLASS, vscp_type, data)), vb.SEND)
        self.assertEqual(self.retr_matching(receiver, vscp_type).data, data)
        self.assertError(sender.command(vb.SEND, vb.event_payload(
            TEST_CLASS, vscp_type, bytes(513))), vb.SEND, vb.PARAMETER)

    def test_malformed_send_arguments(self):
        client = self.connect()
        payload = vb.event_payload(TEST_CLASS, 1, b"\x01\x02")
        self.assertError(client.command(vb.SEND, payload[:-1]), vb.SEND,
                         vb.PARAMETER)

    # -- framing robustness --------------------------------------------------

    def test_fragmented_and_coalesced_frames(self):
        client = self.connect(encryption=3)
        wire = vb.encode(vb.command_frame(vb.GETCHID), 3, SERVER["key"])
        for byte in wire:
            client.send_raw(bytes([byte]))
            time.sleep(0.002)
        self.assertOk(client.read_reply(), vb.GETCHID)
        wire = b"".join(vb.encode(vb.command_frame(code), enc, SERVER["key"])
                        for code, enc in ((vb.NOOP, 0), (vb.VERSION, 1),
                                          (vb.GETCHID, 2), (vb.NOOP, 3)))
        client.send_raw(wire)
        for code in (vb.NOOP, vb.VERSION, vb.GETCHID, vb.NOOP):
            self.assertOk(client.read_reply(), code)

    def expect_resync(self, client, garbage):
        client.send_raw(garbage + vb.encode(vb.command_frame(vb.VERSION)))
        self.assertError(client.read_reply(), vb.ASYNC, vb.INVALID_FRAME)
        self.assertOk(client.read_reply(), vb.VERSION)
        self.assertFalse(client.is_closed(0.2))

    def test_resync_after_garbage(self):
        self.expect_resync(self.connect(), b"hello world\x00\xff")

    def test_resync_after_bad_crc(self):
        wire = bytearray(vb.encode(vb.command_frame(vb.NOOP)))
        wire[-1] ^= 0xFF
        self.expect_resync(self.connect(), bytes(wire))

    def test_resync_after_wrong_framing_version(self):
        self.expect_resync(self.connect(),
                           vb.encode(vb.command_frame(vb.NOOP), version=2))

    def test_resync_after_unknown_frame_type(self):
        frame = vb.with_crc(b"\x20\x00\x00")
        self.expect_resync(self.connect(), vb.encode(frame))

    def test_resync_after_bad_encrypted_length(self):
        self.expect_resync(self.connect(),
                           b"\x55\x20\x22\xe1" + bytes(0x21))

    def test_resync_after_wrong_key(self):
        client = self.connect()
        wire = vb.encode(vb.command_frame(vb.NOOP), 3, bytes(32))
        self.expect_resync(client, wire)

    def test_one_error_per_bad_data_run(self):
        client = self.connect()
        garbage = b"\x55\xff\xff" * 10 + b"junk" * 10
        bad = bytearray(vb.encode(vb.command_frame(vb.NOOP)))
        bad[-1] ^= 1
        self.expect_resync(client, garbage + bytes(bad))
        self.expect_resync(client, b"x")

    def test_reply_frame_from_client_is_rejected(self):
        client = self.connect()
        client.send_frame(vb.with_crc(b"\xF0\x00\x10\x00\x00"))
        self.assertError(client.read_reply(), vb.ASYNC, vb.PARAMETER)
        self.assertOk(client.command(vb.NOOP), vb.NOOP)

    def test_stalled_false_header_times_out(self):
        client = self.connect()
        client.send_raw(b"\x55\x2f\xff\xe0")
        start = time.monotonic()
        client.send_frame(vb.command_frame(vb.NOOP), encryption=1)
        reply = client.read_reply(timeout=6)
        self.assertError(reply, vb.ASYNC, vb.INVALID_FRAME)
        self.assertGreaterEqual(time.monotonic() - start, 1.5)
        reply = client.read_reply()
        self.assertOk(reply, vb.NOOP)
        self.assertEqual(reply.encryption, 1)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--vscpd", help="start this vscpd executable for the test")
    options, rest = parser.parse_known_args()
    if options.vscpd:
        start_daemon(os.path.abspath(options.vscpd))
    else:
        configure_external()
    try:
        program = unittest.main(argv=[sys.argv[0]] + rest, exit=False,
                                verbosity=2)
    finally:
        stop_daemon()
    sys.exit(not program.result.wasSuccessful())


if __name__ == "__main__":
    main()
