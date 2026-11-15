# SPDX-License-Identifier: MIT
"""Read-only bearer diagnostics against synthetic records and one fake owner."""
import env  # noqa: F401
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

import bearer_status
import data_call
import paths
import service
import sit

V4 = bytes.fromhex('c0000201')
V6 = bytes.fromhex('20010db8000000000000000000000001')
PRIVATE = b'private-diagnostic-marker'


def item(cid=3, *, size=132, status=0, active=2, pdp=3, v4=V4, v6=V6):
    body = bytearray(size)
    struct.pack_into('<HBBB', body, 0, status, cid, active, pdp)
    body[5:9], body[9:25] = v4, v6
    body[30:30 + len(PRIVATE)] = PRIVATE
    return bytes(body)


class Owner:
    def __init__(self, payload=None, error=None):
        self.payload = bytes([1]) + item() if payload is None else payload
        self.error = error
        self.sent = []
        self.pending = []
        self.drained = 0

    def request(self, ident, payload=b'', timeout=8):
        if ident != 0x0602 or payload != b'' or timeout != 5:
            raise AssertionError('only one empty GET_DATA_CALL_LIST is allowed')
        sit.check(ident, payload=payload)
        self.sent.append((ident, payload, timeout))
        if self.error:
            raise self.error
        return self.payload

    def next_indication(self, timeout):
        if timeout != 0:
            raise AssertionError('only the normal nonblocking pump is expected')
        self.drained += 1
        return self.pending.pop(0) if self.pending else None


class Fixture:
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'data-session.json'
        self.response = self.root / 'data-call-response.bin'
        for target, name, value in ((data_call, 'STATE', self.state),
                                    (data_call, 'RESPONSE', self.response),
                                    (paths, 'RUN', self.root)):
            active_patch = patch.object(target, name, value)
            active_patch.start()
            self.addCleanup(active_patch.stop)
        self.owned()

    def owned(self, value=None, response=None):
        self.state.write_text(json.dumps(dict(cid=3, session=0) if value is None else value))
        self.response.write_bytes(item() if response is None else response)

    def read(self, owner=None, **kwargs):
        owner = owner or Owner()
        result = bearer_status.read_status(owner, **kwargs)
        self.assertEqual(owner.sent, [(0x0602, b'', 5)])
        return result


class DiagnosticTests(Fixture, unittest.TestCase):
    def test_private_inventory_identifies_other_cids_without_claiming_them(self):
        payload = b'\2' + item(cid=4, pdp=1, v6=bytes(16)) + item(cid=2, pdp=2, v4=bytes(4))
        result = self.read(Owner(payload), inventory=True)
        self.assertEqual(result['owned_cid'], 3)
        self.assertFalse(result['present'])
        self.assertEqual(result['contexts'], [
            dict(cid=2, status=0, active=2, pdp_type=2, ipv4_present=False, ipv6_present=True),
            dict(cid=4, status=0, active=2, pdp_type=1, ipv4_present=True, ipv6_present=False)])
        text = json.dumps(result)
        for private in (PRIVATE.decode(), V4.hex(), V6.hex(), '192.0.2.1', '2001:db8:'):
            self.assertNotIn(private, text)

    def test_all_supported_widths_and_both_active_states(self):
        for size in (132, 234, 239, 246, 280, 292):
            for active in (1, 2):
                with self.subTest(size=size, active=active):
                    record = item(size=size, active=active)
                    self.owned(response=record)
                    result = self.read(Owner(bytes([1]) + record))
                    self.assertEqual(result, dict(status='available', source='modem',
                        owned_cid=3, present=True, bearer_status=0, active=active, pdp_type=3,
                        ipv4_present=True, ipv6_present=True, setup_ipv4_present=True,
                        setup_ipv6_present=True, ipv4_matches_setup=True,
                        ipv6_matches_setup=True, pdp_matches_setup=True))

    def test_missing_owned_cid_does_not_expose_or_claim_foreign_bearers(self):
        for payload in (b'\0', bytes([1]) + item(cid=7)):
            self.assertEqual(self.read(Owner(payload)), dict(status='available', source='modem',
                             owned_cid=3, present=False, reason='owned-bearer-missing'))

    def test_only_the_recorded_cid_is_compared_in_a_multi_bearer_list(self):
        foreign = item(cid=7, pdp=1, v4=bytes.fromhex('c0000207'), v6=bytes(16))
        result = self.read(Owner(bytes([2]) + foreign + item()))
        self.assertEqual(result['owned_cid'], 3)
        self.assertEqual(result['pdp_type'], 3)
        self.assertTrue(result['ipv4_matches_setup'])
        self.assertTrue(result['ipv6_matches_setup'])
        self.assertNotIn('reason', result)

    def test_changed_address_pdp_status_and_inactive_are_fresh(self):
        cases = [(item(v4=bytes.fromhex('c0000202')), 'address-changed'),
                 (item(v6=bytes(16)), 'address-changed'),
                 (item(pdp=1), 'pdp-changed'),
                 (item(active=0), 'owned-bearer-inactive'),
                 (item(status=36), 'owned-bearer-error')]
        for record, reason in cases:
            with self.subTest(reason=reason):
                result = self.read(Owner(bytes([1]) + record))
                self.assertTrue(result['present'])
                self.assertEqual(result['reason'], reason)
                self.assertEqual(result['active'], record[3])
                self.assertEqual(result['pdp_type'], record[4])
        changed = self.read(Owner(bytes([1]) + cases[0][0]))
        self.assertFalse(changed['ipv4_matches_setup'])
        self.assertTrue(changed['ipv6_matches_setup'])

    def test_empty_addresses_never_compare_as_a_known_match(self):
        record = item(v4=bytes(4), v6=bytes(16))
        self.owned(response=record)
        result = self.read(Owner(bytes([1]) + record))
        for family in ('ipv4', 'ipv6'):
            self.assertFalse(result[f'{family}_present'])
            self.assertFalse(result[f'setup_{family}_present'])
            self.assertFalse(result[f'{family}_matches_setup'])

    def test_strict_ownership_types_ranges_and_ims_exclusion(self):
        cases = [[], None, 'private', True, {}, {'cid': 3}, {'session': 0}]
        cases += [dict(cid=cid, session=0) for cid in (True, 3.0, '3', 0, 2, 16)]
        cases += [dict(cid=3, session=session) for session in (True, 0.0, '0', -1, 16)]
        for value in cases:
            with self.subTest(value=value):
                self.state.write_text(json.dumps(value))
                result = self.read(Owner(bytes([1]) + item(cid=7)))
                self.assertEqual(result, dict(status='unknown', source='modem',
                                             reason='invalid-ownership'))
        for cid, session in ((1, 0), (15, 15)):
            self.owned(dict(cid=cid, session=session), item(cid=cid))
            result = self.read(Owner(bytes([1]) + item(cid=cid)))
            self.assertEqual(result['status'], 'available')
            self.assertEqual(result['owned_cid'], cid)

    def test_missing_bad_or_unreadable_ownership_is_unknown(self):
        self.state.unlink()
        self.assertEqual(self.read(), dict(status='unknown', source='modem',
                                          reason='ownership-unavailable'))
        for text in ('{private', '\ud800'):
            if text == '\ud800':
                self.state.write_bytes(b'\xff')
            else:
                self.state.write_text(text)
            self.assertEqual(self.read()['reason'], 'ownership-unavailable')
        with patch.object(Path, 'read_text', side_effect=PermissionError('private')):
            self.assertEqual(self.read()['status'], 'unknown')

    def test_absent_invalid_or_mismatched_setup_is_unknown(self):
        self.response.unlink()
        result = self.read()
        self.assertEqual((result['status'], result['reason']), ('unknown', 'setup-unavailable'))
        self.assertTrue(result['present'])
        for record in [bytes(n) for n in (0, 131, 133, 233, 293)] + [
                item(cid=4), item(status=1), item(active=0), item(active=3), item(pdp=0)]:
            with self.subTest(size=len(record)):
                self.response.write_bytes(record)
                result = self.read()
                self.assertEqual((result['status'], result['reason']), ('unknown', 'invalid-setup'))
                self.assertNotIn('ipv4_matches_setup', result)

    def test_malformed_lists_are_unavailable_without_partial_values(self):
        payloads = [b'', b'\x10', b'\0private', b'\x01' + bytes(131),
                    b'\x02' + item(), b'\x02' + item() + item(),
                    b'\x01' + item(cid=0), b'\x01' + item(cid=16),
                    b'\x01' + item(active=255), b'\x01' + item(pdp=255), 'private']
        for payload in payloads:
            with self.subTest(payload_type=type(payload).__name__):
                result = self.read(Owner(payload))
                self.assertEqual(result, dict(status='unavailable', source='unavailable',
                                             owned_cid=3, reason='unsupported-layout'))

    def test_query_failures_are_fixed_private_and_never_retried(self):
        for error, reason in ((TimeoutError('private'), 'timeout'),
                              (sit.ModemError(7, PRIVATE), 'modem-error'),
                              (EOFError('private'), 'query-unavailable'),
                              (OSError('private'), 'query-unavailable'),
                              (RuntimeError('private'), 'query-unavailable')):
            result = self.read(Owner(error=error))
            self.assertEqual(result, dict(status='unavailable', source='unavailable',
                                         owned_cid=3, reason=reason))

    def test_read_has_no_writes_logs_socket_or_lifecycle_mutations(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                patch.object(data_call, 'private_write', side_effect=AssertionError('write')), \
                patch.object(data_call, 'deactivate', side_effect=AssertionError('release')), \
                patch.object(data_call, 'setup_payload', side_effect=AssertionError('setup')), \
                patch('socket.socket', side_effect=AssertionError('new channel')):
            result = self.read()
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)
        self.assertEqual(out.getvalue() + err.getvalue(), '')
        text = json.dumps(result)
        for secret in (PRIVATE.decode(), V4.hex(), V6.hex(), '192.0.2.1', '2001:db8::1'):
            self.assertNotIn(secret, text)
        labels = {'available', 'modem'}
        self.assertTrue(all(value in labels if isinstance(value, str)
                            else type(value) in (int, bool) for value in result.values()))


class ServiceTests(Fixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.db = service.database(self.root / 'db')
        self.addCleanup(self.db.close)
        self.client = Owner()
        self.app = service.Service(self.client, self.db)

    def socket_request(self, clients, request=None):
        mine, theirs = socket.socketpair()
        self.addCleanup(mine.close)
        self.addCleanup(theirs.close)
        theirs.settimeout(1)
        theirs.sendall(json.dumps(request or dict(action='bearer-status')).encode() + b'\n')
        service.serve_one(self.app, mine, clients)
        return json.loads(theirs.recv(65536))

    def test_authorized_result_is_not_cached_published_stored_or_logged(self):
        before_db = list(self.db.iterdump())
        before_state = dict(self.app.__dict__)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.socket_request({os.getuid()})
            self.assertEqual(self.app.__dict__, before_state)
            self.app.publish()
            self.app.broadcast()
            texts = [json.dumps(self.app.status()), json.dumps(self.app.status(public=True)),
                     (self.root / 'state.json').read_text(), '\n'.join(self.db.iterdump()),
                     out.getvalue(), err.getvalue()]
        self.assertTrue(result['ok'])
        self.assertEqual(result['result']['source'], 'modem')
        self.assertEqual(self.client.sent, [(0x0602, b'', 5)])
        self.assertEqual(list(self.db.iterdump()), before_db)
        for text in texts:
            for private in ('owned_cid', 'matches_setup', 'bearer_status', PRIVATE.decode()):
                self.assertNotIn(private, text)

    def test_unauthorized_request_sends_nothing(self):
        response = self.socket_request(set())
        self.assertFalse(response['ok'])
        self.assertEqual(self.client.sent, [])

    def test_live_calls_and_extra_arguments_are_refused_before_query(self):
        for state in ('active', 'held', 'dialing', 'ringing-in', 'waiting'):
            self.app.calls = {'test': dict(state=state)}
            with self.assertRaisesRegex(RuntimeError, 'current call'):
                self.app.dispatch(dict(action='bearer-status'))
        self.app.calls = {}
        for field in ('cid', 'session', 'payload', 'command', 'interface', 'apn', 'timeout'):
            with self.assertRaises(ValueError):
                self.app.dispatch(dict(action='bearer-status', **{field: 'private'}))
        self.assertEqual(self.client.sent, [])

    def test_pumps_normal_indications_after_success_or_timeout(self):
        for error in (None, TimeoutError('private')):
            self.client.error = error
            packet = object()
            self.client.pending.append(packet)
            with patch.object(self.app, 'event') as event:
                self.app.dispatch(dict(action='bearer-status'))
            event.assert_called_once_with(packet)
            self.assertEqual(self.client.pending, [])

    def test_regular_status_never_triggers_a_query(self):
        self.app.dispatch(dict(action='status'))
        self.app.publish()
        self.app.broadcast()
        self.assertEqual(self.client.sent, [])


if __name__ == '__main__':
    unittest.main()
