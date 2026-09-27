#!/usr/bin/env python3
"""Microsoft simulator TCP transport over the public libtpms C ABI.

Protocol sources: Microsoft ms-tpm-20-ref TPMCmd/Simulator/include/TpmTcpProtocol.h
and TPMCmd/Simulator/src/TcpServer.c; the former is also vendored at
libtpms/src/tpm2/TpmTcpProtocol.h. Handshake v1 advertises platform (1), raw TPM
commands (4), and physical presence (8).

NVRAM lives for this process, including client disconnects and cold power cycles.
No state is restored from an earlier process. POWER_OFF discards volatile runtime;
POWER_ON loads the committed NVRAM through callbacks, without sending TPM Startup.
Warm RESET/RESTART, cancellation pin transitions, NV_OFF, key-cache controls,
failure injection, ACT queries and firmware controls cannot be represented by
the public ABI: the bridge logs the unsupported opcode and closes that channel
without acknowledging it. Some upstream clients ignore numeric error statuses.
NV_ON is idempotent because MainInit enables NV.
As in the reference simulator, physical-presence/cancellation/NV signals and
RESET are acknowledged but ignored while power is off (including MS TSS's
POWER_OFF followed by NV_OFF). Live NV_OFF and warm RESET still fail.
The v1 handshake has no capability bits for these individual limitations.
"""

import argparse
import ctypes as C
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import threading


MAX_FRAME = 1024 * 1024  # Same framing ceiling as Microsoft's TCP simulator.
TPM_FAIL = 9
TPM_RETRY = 0x800
U8 = C.c_ubyte
U32 = C.c_uint32
BYTE_P = C.POINTER(U8)
INIT = C.CFUNCTYPE(U32)
LOAD = C.CFUNCTYPE(U32, C.POINTER(BYTE_P), C.POINTER(U32), U32, C.c_char_p)
STORE = C.CFUNCTYPE(U32, BYTE_P, U32, U32, C.c_char_p)
DELETE = C.CFUNCTYPE(U32, U32, C.c_char_p, U8)
LOCALITY = C.CFUNCTYPE(U32, C.POINTER(U32), U32)
PRESENCE = C.CFUNCTYPE(U32, C.POINTER(U8), U32)


class Callbacks(C.Structure):
    _fields_ = [
        ("sizeOfStruct", C.c_int), ("tpm_nvram_init", INIT),
        ("tpm_nvram_loaddata", LOAD), ("tpm_nvram_storedata", STORE),
        ("tpm_nvram_deletename", DELETE), ("tpm_io_init", INIT),
        ("tpm_io_getlocality", LOCALITY),
        ("tpm_io_getphysicalpresence", PRESENCE),
    ]


class LibraryError(RuntimeError):
    pass


def check(code, operation):
    if code:
        raise LibraryError("%s returned 0x%x" % (operation, code))


class Libtpms:
    """One process-global TPM. The server serializes calls and callback state."""

    def __init__(self, path):
        self.library = C.CDLL(path)
        # Both supported ABIs transfer malloc-owned buffers. The Rust ABI does
        # not export the optional TPM_Malloc/TPM_Free convenience functions.
        self.allocator = C.CDLL(None)
        self.allocator.malloc.argtypes = [C.c_size_t]
        self.allocator.malloc.restype = BYTE_P
        self.allocator.free.argtypes = [C.c_void_p]
        self.allocator.free.restype = None
        self.powered = False
        self.physical_presence = False
        self.locality = 0
        self.nvram = {}
        declarations = {
            "TPMLIB_ChooseTPMVersion": (U32, [C.c_int]),
            "TPMLIB_RegisterCallbacks": (U32, [C.POINTER(Callbacks)]),
            "TPMLIB_MainInit": (U32, []),
            "TPMLIB_Terminate": (None, []),
            "TPMLIB_Process": (U32, [C.POINTER(BYTE_P), C.POINTER(U32),
                                    C.POINTER(U32), BYTE_P, U32]),
            "TPM_IO_Hash_Start": (U32, []),
            "TPM_IO_Hash_Data": (U32, [BYTE_P, U32]),
            "TPM_IO_Hash_End": (U32, []),
        }
        for name, (result, args) in declarations.items():
            function = getattr(self.library, name)
            function.restype = result
            function.argtypes = args

        def guarded(callback_type, function):
            # Exceptions must not escape ctypes callbacks (undefined return value).
            def invoke(*args):
                try:
                    return function(*args)
                except Exception as error:
                    print("bridge callback failed: %s" % error, file=sys.stderr, flush=True)
                    return TPM_FAIL
            return callback_type(invoke)

        self.callbacks = Callbacks(
            C.sizeof(Callbacks), INIT(lambda: 0), guarded(LOAD, self._load),
            guarded(STORE, self._store), guarded(DELETE, self._delete),
            INIT(lambda: 0), guarded(LOCALITY, self._locality),
            guarded(PRESENCE, self._presence))
        check(self.library.TPMLIB_ChooseTPMVersion(1), "ChooseTPMVersion(TPM2)")
        check(self.library.TPMLIB_RegisterCallbacks(C.byref(self.callbacks)), "RegisterCallbacks")

    def _load(self, data, length, number, name):
        data[0] = BYTE_P()
        length[0] = 0
        value = self.nvram.get((number, name))
        if value is None:
            return TPM_RETRY
        allocation = self.allocator.malloc(max(1, len(value)))
        if not allocation:
            return TPM_FAIL
        C.memmove(allocation, value, len(value))
        data[0] = allocation  # Ownership transfers to libtpms, which frees it.
        length[0] = len(value)
        return 0

    def _store(self, data, length, number, name):
        self.nvram[(number, name)] = C.string_at(data, length)
        return 0

    def _delete(self, number, name, must_exist):
        key = (number, name)
        if key not in self.nvram and must_exist:
            return TPM_FAIL
        self.nvram.pop(key, None)
        return 0

    def _locality(self, value, number):
        value[0] = self.locality
        return 0

    def _presence(self, value, number):
        value[0] = self.physical_presence
        return 0

    def power_on(self):
        if self.powered:
            return
        check(self.library.TPMLIB_ChooseTPMVersion(1), "ChooseTPMVersion(TPM2)")
        code = self.library.TPMLIB_MainInit()
        if code:
            self.library.TPMLIB_Terminate()
            check(code, "MainInit")
        self.powered = True

    def power_off(self):
        if self.powered:
            self.library.TPMLIB_Terminate()
            self.powered = False
        # A cold boot must not resume an imported volatile runtime image.
        for key in list(self.nvram):
            if key[1] == b"volatilestate":
                del self.nvram[key]

    def process(self, body, locality):
        if not self.powered:
            return b""  # _rpc__Send_Command returns an empty response while off.
        self.locality = locality
        data = (U8 * len(body)).from_buffer_copy(body)
        response = BYTE_P()
        size, capacity = U32(), U32()
        try:
            check(self.library.TPMLIB_Process(C.byref(response), C.byref(size),
                  C.byref(capacity), data, len(body)), "Process")
            if size.value > MAX_FRAME or size.value > capacity.value:
                raise LibraryError("library returned an invalid response size")
            if size.value and not response:
                raise LibraryError("library returned a null response buffer")
            return C.string_at(response, size.value)
        finally:
            self.allocator.free(response)

    def hash_signal(self, opcode, body=b""):
        if not self.powered:
            return
        if opcode == 6:
            data = (U8 * len(body)).from_buffer_copy(body)
            check(self.library.TPM_IO_Hash_Data(data, len(body)), "Hash_Data")
        elif opcode == 5:
            check(self.library.TPM_IO_Hash_Start(), "Hash_Start")
        else:
            check(self.library.TPM_IO_Hash_End(), "Hash_End")

    def close(self):
        self.power_off()


def u32(value):
    return struct.pack(">I", value)


class Server:
    def __init__(self, tpm, host, port, platform_port, trace_errors=False):
        self.tpm = tpm
        self.trace_errors = trace_errors
        self.done = threading.Event()
        self.tpm_lock = threading.Lock()
        self.clients_lock = threading.Lock()
        self.clients = set()
        self.workers = []
        self.listeners = []
        try:
            for number in (port, platform_port):
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.listeners.append(listener)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((host, number))
                listener.listen(16)
                listener.settimeout(0.2)
        except Exception:
            for listener in self.listeners:
                listener.close()
            raise
        self.port = self.listeners[0].getsockname()[1]
        self.platform_port = self.listeners[1].getsockname()[1]

    def stop(self):
        self.done.set()
        for listener in self.listeners:
            listener.close()
        with self.clients_lock:
            for client in self.clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve(self):
        acceptors = [threading.Thread(target=self._accept, args=(listener, bool(index)))
                     for index, listener in enumerate(self.listeners)]
        for thread in acceptors:
            thread.start()
        try:
            self.done.wait()
        finally:
            self.stop()
            for thread in acceptors:
                thread.join()
            for thread in self.workers:
                thread.join()
            self.tpm.close()

    def _accept(self, listener, platform):
        while not self.done.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if not self.done.is_set():
                    self.stop()
                return
            client.settimeout(0.2)
            with self.clients_lock:
                if self.done.is_set():
                    client.close()
                    return
                self.clients.add(client)
            thread = threading.Thread(target=self._client, args=(client, platform))
            self.workers.append(thread)
            thread.start()

    def _receive(self, client, size):
        result = bytearray()
        while len(result) < size:
            if self.done.is_set():
                raise EOFError
            try:
                data = client.recv(size - len(result))
            except socket.timeout:
                continue
            if not data:
                raise EOFError
            result.extend(data)
        return bytes(result)

    def _number(self, client):
        return struct.unpack(">I", self._receive(client, 4))[0]

    def _buffer(self, client):
        size = self._number(client)
        if size > MAX_FRAME:
            raise ValueError("frame exceeds 1 MiB limit")
        return self._receive(client, size)

    def _client(self, client, platform):
        try:
            while not self.done.is_set():
                opcode = self._number(client)
                if opcode == 20:
                    return  # SESSION_END has no acknowledgement, on either channel.
                if opcode == 21:
                    self.stop()
                    return  # STOP has no acknowledgement.
                if platform:
                    with self.tpm_lock:
                        if opcode == 1:
                            self.tpm.power_on()
                        elif opcode == 2:
                            self.tpm.power_off()
                        elif opcode in (3, 4):
                            if self.tpm.powered:
                                self.tpm.physical_presence = opcode == 3
                        elif opcode == 11:
                            pass  # NV is always available while powered on.
                        elif opcode in (9, 10, 12, 17) and not self.tpm.powered:
                            # TPMCmdp.c ignores these signals while powered off.
                            # In particular, MS TSS PowerOff sends NV_OFF after
                            # POWER_OFF; acknowledging that sequence is exact.
                            pass
                        else:
                            self._unsupported(opcode)
                            return
                    client.sendall(u32(0))
                elif opcode == 15:
                    if self._number(client) == 0:
                        return
                    client.sendall(u32(1) + u32(0x0d) + u32(0))
                elif opcode == 8:
                    locality = self._receive(client, 1)[0]
                    body = self._buffer(client)
                    try:
                        with self.tpm_lock:
                            response = self.tpm.process(body, locality)
                        if self.trace_errors:
                            self._trace(body, response)
                        client.sendall(u32(len(response)) + response + u32(0))
                    except LibraryError as error:
                        print("bridge: %s" % error, file=sys.stderr, flush=True)
                        client.sendall(u32(0) + u32(1))
                elif opcode in (5, 6, 7):
                    body = self._buffer(client) if opcode == 6 else b""
                    with self.tpm_lock:
                        self.tpm.hash_signal(opcode, body)
                    client.sendall(u32(0))
                else:
                    self._unsupported(opcode)
                    return
        except (EOFError, ConnectionError):
            pass
        except (ValueError, LibraryError) as error:
            print("bridge: %s" % error, file=sys.stderr, flush=True)
        except OSError as error:
            if not self.done.is_set():
                print("bridge socket: %s" % error, file=sys.stderr, flush=True)
        finally:
            with self.clients_lock:
                self.clients.discard(client)
            client.close()

    @staticmethod
    def _trace(body, response):
        # Evidence only: the response code the library returned, never altered.
        if len(body) >= 10 and len(response) >= 10:
            code = struct.unpack(">I", response[6:10])[0]
            if code:
                print("bridge: command 0x%08x response 0x%08x"
                      % (struct.unpack(">I", body[6:10])[0], code), file=sys.stderr, flush=True)

    @staticmethod
    def _unsupported(opcode):
        print("bridge: unsupported simulator opcode %d" % opcode, file=sys.stderr, flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--library", default=os.environ.get("LIBTPMS_LIBRARY"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", "-port", type=int)
    parser.add_argument("--platform-port", type=int)
    parser.add_argument("command_port", nargs="?", type=int)
    parser.add_argument("--pick_ports", action="store_true")
    parser.add_argument("--ready-file", type=Path,
                        help="atomically publish PID and bound ports as JSON after listening")
    parser.add_argument("-m", "--manufacture", action="store_true",
                        help="start with fresh NVRAM (always enabled)")
    parser.add_argument("-e", action="store_true", help="ephemeral NVRAM (always enabled)")
    parser.add_argument("--trace-errors", action="store_true",
                        help="log the command and response code of every failing TPM response")
    parser.add_argument("--process-name", help="Linux process name for upstream simulator discovery")
    args = parser.parse_args(argv)
    if not args.library:
        parser.error("--library or LIBTPMS_LIBRARY is required; there is no default TPM backend")
    if args.port is not None and args.command_port is not None:
        parser.error("choose --port or a positional command port")
    port = args.port if args.port is not None else args.command_port
    port = 2321 if port is None else port
    platform_port = args.platform_port if args.platform_port is not None else port + 1
    if not 0 <= port <= 65535 or not 0 <= platform_port <= 65535:
        parser.error("ports must be between 0 and 65535")
    if args.pick_ports:
        port = platform_port = 0
    files = []
    server = None

    def publish(path, contents):
        temporary = path.with_name(path.name + ".tmp.%d" % os.getpid())
        try:
            temporary.write_text(contents + "\n", encoding="ascii")
            temporary.replace(path)
            files.append(path)
        finally:
            temporary.unlink(missing_ok=True)

    try:
        if args.process_name:
            if not sys.platform.startswith("linux"):
                raise ValueError("--process-name requires Linux")
            if len(args.process_name.encode()) > 15:
                raise ValueError("--process-name must fit in 15 bytes")
            libc = C.CDLL(None, use_errno=True)
            if libc.prctl(15, C.c_char_p(args.process_name.encode()), 0, 0, 0):
                raise OSError(C.get_errno(), "prctl(PR_SET_NAME) failed")
        tpm = Libtpms(args.library)
        server = Server(tpm, args.host, port, platform_port, args.trace_errors)
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda signum, frame: server.stop())
        if args.pick_ports:
            for name, number in (("platform.port", server.platform_port), ("command.port", server.port)):
                publish(Path(name), str(number))
        if args.ready_file:
            publish(args.ready_file, json.dumps({"pid": os.getpid(), "host": args.host,
                    "port": server.port, "platform_port": server.platform_port}))
        print("libtpms bridge ready: %s:%d platform:%d library:%s" %
              (args.host, server.port, server.platform_port, args.library), flush=True)
        server.serve()
        return 0
    except (OSError, ValueError, AttributeError, LibraryError) as error:
        print("bridge: %s" % error, file=sys.stderr)
        return 1
    finally:
        if server:
            server.stop()
        for path in files:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
