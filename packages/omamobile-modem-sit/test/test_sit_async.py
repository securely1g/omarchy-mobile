# SPDX-License-Identifier: MIT
"""One socket owner multiplexes recovery replies with normal call/SMS work."""
import env  # noqa: F401
from collections import deque
import os
import socket
import struct
import threading
import unittest
from unittest.mock import patch

import sit


def reply(ident, token, payload=b'', error=0):
    return struct.pack('<BBHHIBB', 1, 0, ident, 12 + len(payload), token, error, 0) + payload


def indication(ident, payload=b''):
    return struct.pack('<BBHHH', 2, 0, ident, 8 + len(payload), 0) + payload


class SocketOwnerFixture(unittest.TestCase):
    def setUp(self):
        self.local, self.peer = socket.socketpair()
        self.addCleanup(self.local.close)
        self.addCleanup(self.peer.close)
        self.local.setblocking(False)
        self.peer.settimeout(1)
        self.client = sit.Sit.__new__(sit.Sit)
        self.client.fd, self.client.token = self.local.fileno(), 100
        self.client.buffer, self.client.indications = bytearray(), deque()

    def begin(self, ident=0x0600, timeout=1):
        handle = self.client.begin_request(ident, timeout=timeout)
        request = self.peer.recv(4096)
        return handle, struct.unpack_from('<I', request, 6)[0]


class AsyncTransportTests(SocketOwnerFixture):
    def test_normal_request_and_async_setup_route_both_reply_orders(self):
        for async_first in (True, False):
            with self.subTest(async_first=async_first):
                handle, token = self.begin()
                call = indication(0x0d01)
                sms = indication(0x0d1e)
                def respond():
                    request = self.peer.recv(4096)
                    normal = reply(0x0200, struct.unpack_from('<I', request, 6)[0], b'normal')
                    pending = reply(0x0600, token, b'setup')
                    self.peer.sendall(call + (pending + normal if async_first else normal + pending) + sms)
                worker = threading.Thread(target=respond)
                worker.start()
                self.assertEqual(self.client.request(0x0200, timeout=.5), b'normal')
                worker.join(1)
                self.assertFalse(worker.is_alive())
                self.assertTrue(self.client.drain_ready())
                self.assertEqual(self.client.poll_request(handle), b'setup')
                self.assertEqual(self.client.next_indication(0), call)
                self.assertEqual(self.client.next_indication(0), sms)

    def test_async_modem_error_does_not_escape_into_normal_caller(self):
        handle, token = self.begin()
        def respond():
            request = self.peer.recv(4096)
            self.peer.sendall(reply(0x0600, token, b'private', 2)
                              + reply(0x0200, struct.unpack_from('<I', request, 6)[0], b'ok'))
        worker = threading.Thread(target=respond)
        worker.start()
        self.assertEqual(self.client.request(0x0200, timeout=.5), b'ok')
        worker.join(1)
        with self.assertRaises(sit.ModemError):
            self.client.poll_request(handle)
        self.assertFalse(self.client.pending)

    def test_cancel_and_late_reply_never_retransmit_or_complete_other_request(self):
        handle, token = self.begin()
        self.client.cancel_request(handle)
        def respond():
            request = self.peer.recv(4096)
            self.peer.sendall(reply(0x0600, token, b'late')
                              + reply(0x0200, struct.unpack_from('<I', request, 6)[0], b'normal'))
        worker = threading.Thread(target=respond)
        worker.start()
        self.assertEqual(self.client.request(0x0200, timeout=.5), b'normal')
        worker.join(1)
        with self.assertRaises(ValueError):
            self.client.poll_request(handle)
        self.peer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.peer.recv(1)

    def test_timeout_is_independent_and_late_reply_is_ignored(self):
        old, old_token = self.begin()
        old.deadline = -1
        new, new_token = self.begin(0x0701)
        with self.assertRaises(TimeoutError):
            self.client.poll_request(old)
        self.peer.sendall(reply(0x0600, old_token, b'late') + reply(0x0701, new_token, b'new'))
        self.client.drain_ready()
        self.assertEqual(self.client.poll_request(new), b'new')

    def test_fragmented_and_wrong_token_or_ident_do_not_complete_handle(self):
        handle, token = self.begin()
        good = reply(0x0600, token, b'complete')
        self.peer.sendall(reply(0x0701, token) + reply(0x0600, token + 1) + good[:3])
        self.assertFalse(self.client.drain_ready())
        self.assertIsNone(self.client.poll_request(handle))
        self.peer.sendall(good[3:])
        self.assertTrue(self.client.drain_ready())
        self.assertEqual(self.client.poll_request(handle), b'complete')

    def test_capacity_includes_completed_handles_until_consumed(self):
        pairs = [self.begin() for _ in range(4)]
        with self.assertRaisesRegex(RuntimeError, 'limit'):
            self.client.begin_request(0x0701)
        first, token = pairs[0]
        self.peer.sendall(reply(0x0600, token))
        self.client.drain_ready()
        with self.assertRaisesRegex(RuntimeError, 'limit'):
            self.client.begin_request(0x0701)
        self.assertEqual(self.client.poll_request(first), b'')
        self.begin(0x0701)

    def test_wrap_skips_pending_and_old_handle_cannot_read_reused_token(self):
        self.client.token = 0xffffffff
        old, old_token = self.begin()
        self.assertEqual(old_token, 0)
        self.client.token = 0xffffffff
        second, second_token = self.begin()
        self.assertEqual(second_token, 1)
        self.client.cancel_request(old)
        self.client.token = 0xffffffff
        new, token = self.begin()
        self.assertEqual(token, 0)
        with self.assertRaises(ValueError):
            self.client.poll_request(old)
        self.assertIsNone(self.client.poll_request(new))
        self.client.cancel_request(second)

    def test_partial_write_has_no_local_wait_and_no_second_write(self):
        with patch.object(sit.os, 'write', return_value=3) as write:
            with self.assertRaisesRegex(RuntimeError, 'short'):
                self.client.begin_request(0x0600)
        write.assert_called_once()
        self.assertFalse(self.client.pending)

    def test_guards_and_bad_deadlines_write_nothing(self):
        for ident in (0x0001, 0x0100, 0x0d00, 0x0d1b, 0x020c, 0x0401):
            with self.assertRaises(ValueError):
                self.client.begin_request(ident)
        for timeout in (0, -1, float('inf'), float('nan'), True):
            with self.assertRaises(ValueError):
                self.client.begin_request(0x0600, timeout=timeout)
        self.peer.setblocking(False)
        with self.assertRaises(BlockingIOError):
            self.peer.recv(1)

    def test_eof_cleans_normal_wait_without_resending_async(self):
        handle, _ = self.begin()
        self.peer.shutdown(socket.SHUT_WR)
        with self.assertRaises(EOFError):
            self.client.request(0x0200, timeout=.1)
        self.assertEqual(list(self.client.pending.values()), [handle])

    def test_close_invalidates_every_handle_without_writing(self):
        handle, _ = self.begin()
        with patch.object(sit.os, 'close') as close:
            self.client.lock = 1234
            self.client.close()
        self.assertEqual(close.call_count, 2)
        with self.assertRaisesRegex(RuntimeError, 'closed'):
            self.client.poll_request(handle)
        self.assertFalse(self.client.pending)

    def test_telemetry_flood_keeps_calls_sms_and_pending_reply(self):
        handle, token = self.begin()
        call, sms = indication(0x0d01), indication(0x0d1e)
        packets = [call, sms] + [indication(0x0742, struct.pack('<I', n)) for n in range(400)]
        self.peer.sendall(b''.join(packets) + reply(0x0600, token, b'ok'))
        self.assertFalse(self.client.drain_ready(256))
        self.assertTrue(self.client.drain_ready(256))
        self.assertEqual(self.client.next_indication(0), call)
        self.assertEqual(self.client.next_indication(0), sms)
        self.assertEqual(struct.unpack_from('<I', self.client.next_indication(0), 8)[0], 399)
        self.assertEqual(self.client.poll_request(handle), b'ok')


class ServiceResponsivenessTests(SocketOwnerFixture):
    def setUp(self):
        super().setUp()
        import tempfile
        from pathlib import Path
        import paths
        import service
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in (('RUN', self.root), ('INBOX', self.root / 'inbox')):
            p = patch.object(paths, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.db = service.database(self.root / 'db')
        self.addCleanup(self.db.close)
        self.app = service.Service(self.client, self.db)
        self.client.allow_calls = self.client.allow_sms = True

    def test_actual_ring_and_socket_accept_work_while_setup_is_pending(self):
        import json
        import service
        handle, token = self.begin()
        caller = b'+12025550123'
        ring = indication(0x0d01, struct.pack('<HBH', 1, 7, len(caller)) + caller)
        self.peer.sendall(ring)
        self.app.event(self.client.next_indication(.1))
        self.assertEqual(len(self.app.live()), 1)
        self.assertEqual(self.app.live()[0]['state'], 'ringing-in')
        call_id = self.app.live()[0]['id']
        mine, theirs = socket.socketpair()
        self.addCleanup(mine.close)
        self.addCleanup(theirs.close)
        theirs.settimeout(1)
        theirs.sendall(json.dumps({'action': 'accept', 'id': call_id}).encode() + b'\n')
        received = []
        def respond():
            request = self.peer.recv(4096)
            received.append(struct.unpack_from('<H', request, 2)[0])
            normal_token = struct.unpack_from('<I', request, 6)[0]
            self.peer.sendall(reply(0x0600, token, b'setup') + reply(0x0d02, normal_token))
        worker = threading.Thread(target=respond)
        worker.start()
        with patch.object(self.app, 'audio_start'):
            service.serve_one(self.app, mine, {os.getuid()})
        worker.join(1)
        self.assertEqual(received, [0x0d02])
        self.assertTrue(json.loads(theirs.recv(4096))['ok'])
        self.assertEqual(self.client.poll_request(handle), b'setup')

    def test_actual_sms_persist_and_ack_work_while_setup_is_pending(self):
        handle, token = self.begin()
        sms = indication(0x0d1e, b'\x07\x01x')
        self.peer.sendall(sms)
        received = []
        def respond():
            request = self.peer.recv(4096)
            received.append(struct.unpack_from('<H', request, 2)[0])
            normal_token = struct.unpack_from('<I', request, 6)[0]
            self.peer.sendall(reply(0x0600, token, b'setup') + reply(0x0d1d, normal_token))
        worker = threading.Thread(target=respond)
        worker.start()
        with patch.object(self.app, 'ingest') as ingest:
            self.app.event(self.client.next_indication(.1))
        worker.join(1)
        self.assertEqual(received, [0x0d1d])
        stored, = (self.root / 'inbox').glob('*.sit')
        self.assertEqual(stored.read_bytes(), sms)
        self.assertEqual(stored.stat().st_mode & 0o777, 0o600)
        ingest.assert_called_once_with(stored)
        self.assertEqual(self.client.poll_request(handle), b'setup')


if __name__ == '__main__':
    unittest.main()
