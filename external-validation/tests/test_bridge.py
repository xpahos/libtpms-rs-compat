"""Transport tests and opt-in real ABI smoke tests (LIBTPMS_LIBRARY)."""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BRIDGE = Path(__file__).resolve().parents[1] / "bridge.py"


def u32(value):
    return struct.pack(">I", value)


def receive(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("connection closed")
        data += chunk
    return data


def command(sock, body, locality=0):
    sock.sendall(u32(8) + bytes([locality]) + u32(len(body)) + body)
    size = struct.unpack(">I", receive(sock, 4))[0]
    result = receive(sock, size)
    status = struct.unpack(">I", receive(sock, 4))[0]
    if status:
        raise RuntimeError("bridge transport status %d" % status)
    return result


class EchoTPM:
    """Boundary substitute; framing tests do not require a TPM installation."""

    def __init__(self):
        self.powered = False
        self.physical_presence = False

    def power_on(self):
        self.powered = True

    def power_off(self):
        self.powered = False

    def process(self, body, locality):
        if not self.powered:
            return b""
        return bytes([locality, self.physical_presence]) + body

    def close(self):
        self.power_off()


class ProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert BRIDGE.is_file(), "simulator bridge has not been implemented"
        spec = importlib.util.spec_from_file_location("external_bridge", BRIDGE)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def setUp(self):
        self.server = self.module.Server(EchoTPM(), "127.0.0.1", 0, 0)
        self.worker = threading.Thread(target=self.server.serve)
        self.worker.start()
        self.addCleanup(self.cleanup)

    def cleanup(self):
        self.server.stop()
        self.worker.join(3)
        self.assertFalse(self.worker.is_alive(), "server did not stop")

    def connect(self, platform=False):
        port = self.server.platform_port if platform else self.server.port
        conn = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.addCleanup(conn.close)
        return conn

    def platform(self, code):
        with self.connect(True) as conn:
            conn.sendall(u32(code))
            return struct.unpack(">I", receive(conn, 4))[0]

    def test_partial_handshake_and_pipelined_frames(self):
        conn = self.connect()
        for byte in u32(15) + u32(1):
            conn.sendall(bytes([byte]))
        self.assertEqual(receive(conn, 12), u32(1) + u32(13) + u32(0))
        self.assertEqual(self.platform(1), 0)
        body = b"\x80\x01\x00\x00\x00\x0a\x00\x00\x01\x7b"
        frame = u32(8) + b"\x03" + u32(len(body)) + body
        conn.sendall(frame + frame)
        expected = u32(12) + b"\x03\x00" + body + u32(0)
        self.assertEqual(receive(conn, 40), expected * 2)

    def test_presence_locality_and_power_persist_across_connections(self):
        self.assertEqual(self.platform(1), 0)
        self.assertEqual(self.platform(3), 0)
        with self.connect() as conn:
            self.assertEqual(command(conn, b"payload", 4), b"\x04\x01payload")
            conn.sendall(u32(20))
            self.assertEqual(conn.recv(1), b"")
        with self.connect() as conn:
            self.assertEqual(command(conn, b"next"), b"\x00\x01next")
        self.assertEqual(self.platform(2), 0)
        with self.connect() as conn:
            self.assertEqual(command(conn, b"off"), b"")

    def test_oversized_and_truncated_frames_only_close_that_client(self):
        with self.connect() as conn:
            conn.sendall(u32(8) + b"\x00" + u32(1048577))
            self.assertEqual(conn.recv(1), b"")
        with self.connect() as conn:
            conn.sendall(u32(8) + b"\x00" + u32(10) + b"short")
            conn.shutdown(socket.SHUT_WR)
            self.assertEqual(conn.recv(1), b"")
        with self.connect() as conn:
            conn.sendall(u32(15) + u32(1))
            self.assertEqual(receive(conn, 12), u32(1) + u32(13) + u32(0))

    def test_error_trace_is_opt_in_and_leaves_responses_unchanged(self):
        import contextlib, io
        body = b"\x80\x01" + u32(12) + u32(0x176) + b"\x00\x00"
        for trace in (False, True):
            server = self.module.Server(EchoTPM(), "127.0.0.1", 0, 0, trace_errors=trace)
            worker = threading.Thread(target=server.serve)
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                worker.start()
                try:
                    with socket.create_connection(("127.0.0.1", server.platform_port), 2) as p:
                        p.sendall(u32(1))
                        self.assertEqual(receive(p, 4), u32(0))
                    with socket.create_connection(("127.0.0.1", server.port), 2) as conn:
                        # EchoTPM's response carries bytes 4..8 of the body as its code.
                        self.assertEqual(command(conn, body), b"\x00\x00" + body)
                finally:
                    server.stop()
                    worker.join(3)
            expected = "bridge: command 0x00000176 response 0x000c0000\n"
            self.assertEqual(captured.getvalue(), expected if trace else "")

    def test_unsupported_platform_actions_fail_and_do_not_reset(self):
        self.assertEqual(self.platform(1), 0)
        for opcode in (9, 10, 12, 13, 14, 17, 18, 30):
            with self.subTest(opcode=opcode):
                # Canonical's platform client ignores numeric acknowledgement
                # values, so an unsupported control must fail the read itself.
                with self.assertRaises(EOFError):
                    self.platform(opcode)
        self.assertEqual(self.platform(11), 0)
        with self.connect() as conn:
            self.assertEqual(command(conn, b"alive"), b"\x00\x00alive")

    def test_powered_off_controls_follow_reference_noop_semantics(self):
        # MS TSS PowerCycle sends POWER_OFF, NV_OFF, POWER_ON, NV_ON.
        # TPMCmdp.c ignores NV_OFF (and these other signals) while powered off.
        for opcode in (3, 9, 10, 12, 17):
            self.assertEqual(self.platform(opcode), 0)
        self.assertEqual(self.platform(1), 0)
        with self.connect() as conn:
            self.assertEqual(command(conn, b"boot"), b"\x00\x00boot")

    def test_stop_on_either_channel_stops_idle_clients(self):
        idle = self.connect()
        with self.connect(True) as conn:
            conn.sendall(u32(21))
            self.assertEqual(conn.recv(1), b"")
        self.worker.join(3)
        self.assertFalse(self.worker.is_alive())
        self.assertEqual(idle.recv(1), b"")


@unittest.skipUnless(os.environ.get("LIBTPMS_LIBRARY"), "set LIBTPMS_LIBRARY for real ABI tests")
class LibraryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="libtpms-bridge-")
        self.addCleanup(self.temp.cleanup)
        self.ready = Path(self.temp.name) / "ready.json"
        self.process = subprocess.Popen(
            [sys.executable, str(BRIDGE), "--pick_ports", "--ready-file", str(self.ready)], cwd=self.temp.name,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.cleanup)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                out, err = self.process.communicate()
                self.fail("bridge exited at startup: %s %s" % (out, err))
            try:
                self.port = int((Path(self.temp.name) / "command.port").read_text())
                self.platform_port = int((Path(self.temp.name) / "platform.port").read_text())
                ready = json.loads(self.ready.read_text())
                self.assertEqual(ready["pid"], self.process.pid)
                self.assertEqual(ready["port"], self.port)
                self.assertEqual(ready["platform_port"], self.platform_port)
                break
            except (FileNotFoundError, ValueError):
                time.sleep(0.02)
        else:
            self.fail("bridge did not publish its ports")
        self.signal_platform(1)
        self.sock = self.connect()
        self.addCleanup(self.sock.close)
        self.assertEqual(command(self.sock, bytes.fromhex("80010000000c000001440000")),
                         bytes.fromhex("80010000000a00000000"))

    def cleanup(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.communicate()
            self.fail("bridge ignored SIGTERM")

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def signal_platform(self, code):
        with socket.create_connection(("127.0.0.1", self.platform_port), timeout=5) as conn:
            conn.sendall(u32(code))
            self.assertEqual(receive(conn, 4), u32(0))

    def test_nv_survives_power_cycle_and_commands_survive_reconnect(self):
        # Owner-authorized four-byte NV index; auth area is an empty password session.
        define = bytes.fromhex(
            "80020000002d0000012a4000000100000009400000090000000000"
            "0000000e01000001000b0002000200000004")
        write = bytes.fromhex(
            "80020000002700000137400000010100000100000009400000090000000000"
            "0004616263640000")
        read = bytes.fromhex(
            "8002000000230000014e40000001010000010000000940000009000000000000040000")
        for request in (define, write):
            self.assertEqual(struct.unpack(">I", command(self.sock, request)[6:10])[0], 0)
        self.sock.close()
        with self.connect() as conn:
            result = command(conn, read)
            self.assertEqual(result[6:10], u32(0))
            self.assertEqual(result[14:20], b"\x00\x04abcd")
        self.signal_platform(2)
        self.signal_platform(12)
        self.signal_platform(1)
        self.signal_platform(11)
        with self.connect() as conn:
            self.assertEqual(command(conn, bytes.fromhex("80010000000c000001440000"))[6:10], u32(0))
            result = command(conn, read)
            self.assertEqual(result[6:10], u32(0))
            self.assertEqual(result[14:20], b"\x00\x04abcd")

    def test_repeated_power_on_does_not_reset_and_stop_exits(self):
        self.signal_platform(1)
        with self.connect() as conn:
            self.assertEqual(command(conn, bytes.fromhex("80010000000c000001440000"))[6:10], u32(0x100))
            response = command(conn, bytes.fromhex("80010000000c0000017b0010"))
            self.assertEqual(response[6:10], u32(0))
            self.assertGreater(len(response), 12)
            conn.sendall(u32(21))
        self.assertEqual(self.process.wait(timeout=5), 0)
        self.assertFalse((Path(self.temp.name) / "command.port").exists())
        self.assertFalse(self.ready.exists())

    def test_occupied_port_never_publishes_ready_file(self):
        ready = Path(self.temp.name) / "second-ready.json"
        result = subprocess.run(
            [sys.executable, str(BRIDGE), "--port", str(self.port),
             "--platform-port", "0", "--ready-file", str(ready)],
            cwd=self.temp.name, capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(ready.exists())
        self.assertIn("Address already in use", result.stderr)

    def test_locality_and_physical_presence_reach_library_callbacks(self):
        reset = bytes.fromhex("80020000001b0000013d0000001400000009400000090000000000")
        self.assertEqual(command(self.sock, reset, locality=0)[6:10], u32(0x907))
        self.assertEqual(command(self.sock, reset, locality=2)[6:10], u32(0))
        pp = bytes.fromhex(
            "8002000000230000012d4000000c00000009400000090000000000"
            "0000000000000000")
        self.assertEqual(command(self.sock, pp)[6:10], u32(0x990))  # PP, session 1.
        self.signal_platform(3)
        self.assertEqual(command(self.sock, pp)[6:10], u32(0))
        self.signal_platform(4)
        self.assertEqual(command(self.sock, pp)[6:10], u32(0x990))

    def test_cold_power_cycle_discards_volatile_pcr(self):
        read = bytes.fromhex("8001000000140000017e00000001000b03000001")
        extend = bytes.fromhex(
            "80020000004100000182000000100000000940000009000000000000000001000b") + b"\x01" * 32
        self.assertEqual(command(self.sock, read)[-32:], bytes(32))
        self.assertEqual(command(self.sock, extend)[6:10], u32(0))
        self.assertEqual(command(self.sock, read)[-32:], hashlib.sha256(bytes(32) + b"\x01" * 32).digest())
        self.signal_platform(2)
        self.signal_platform(1)
        self.assertEqual(command(self.sock, bytes.fromhex("80010000000c000001440000"))[6:10], u32(0))
        self.assertEqual(command(self.sock, read)[-32:], bytes(32))


if __name__ == "__main__":
    unittest.main()
