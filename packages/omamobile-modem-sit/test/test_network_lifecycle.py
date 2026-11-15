# SPDX-License-Identifier: MIT
import env  # noqa: F401
from contextlib import ExitStack
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import network_lifecycle as protocol


def response(cid=3, address=b'\xc0\x00\x02\x0a', dns=b'\xc0\x00\x02\x35'):
    item = bytearray(132)
    struct.pack_into('<HBBB', item, 0, 0, cid, 1, 3)
    item[5:9] = address
    item[0x1a:0x1e] = dns
    return bytes(item)


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name in ('STATE', 'ACK', 'LEASE', 'OWNED'):
            self.stack.enter_context(patch.object(protocol, name, self.root / name))
        self.stack.enter_context(patch.object(protocol, 'clock', lambda: 100.0))
        self.epoch = 'a' * 32
        self.binding = dict(dev='rmnet2', ifindex=7)
        self.state = protocol.publish_state(self.epoch, 0, 'active', 3, response=response())

    def test_private_atomic_state_and_matching_ack_lease(self):
        self.assertEqual(protocol.read_state(), self.state)
        self.assertEqual(protocol.configuration(self.state), ('192.0.2.10', ['192.0.2.53']))
        protocol.publish_ack(self.state, 'applied', binding=self.binding)
        protocol.publish_lease(self.state, desired=True, awake=True, binding=self.binding)
        self.assertEqual(protocol.read_ack(self.epoch, 0)['binding'], self.binding)
        self.assertIsNone(protocol.read_ack(self.epoch, 1))
        self.assertIsNone(protocol.read_lease(self.epoch, now=106))
        self.assertIsNone(protocol.read_lease(self.epoch, now=99))
        self.assertTrue(protocol.read_lease(self.epoch, now=105)['desired'])
        for path in (protocol.STATE, protocol.ACK, protocol.LEASE):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_writer_never_publishes_a_partial_record(self):
        replace = os.replace
        previous = self.state
        def inspect_before_replace(source, target):
            self.assertEqual(protocol.read_state(), previous)
            self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
            replace(source, target)
        with patch.object(protocol.os, 'replace', inspect_before_replace):
            new = protocol.publish_state(self.epoch, 1, 'quiesce', 3, binding=self.binding)
        self.assertEqual(protocol.read_state(), new)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['STATE'])

    def test_changed_epoch_cid_binding_and_nonsequential_generation_refuse(self):
        for kwargs in (dict(epoch='b' * 32), dict(cid=4), dict(generation=2)):
            request = dict(epoch=self.epoch, generation=1, phase='quiesce', cid=3, binding=self.binding)
            request.update(kwargs)
            with self.assertRaises(protocol.ProtocolError):
                protocol.publish_state(**request)
            self.assertEqual(protocol.read_state(), self.state)
        protocol.publish_state(self.epoch, 1, 'quiesce', 3, binding=self.binding)
        with self.assertRaises(protocol.ProtocolError):
            protocol.publish_state(self.epoch, 2, 'active', 3, response=response(),
                                   binding=dict(dev='rmnet3', ifindex=8))

    def test_malformed_or_private_data_in_fields_is_not_accepted_or_echoed(self):
        cases = [dict(generation=True), dict(cid=2), dict(extra='private'),
                 dict(response_hex='00'), dict(reason='private.example'),
                 dict(binding=dict(dev='wlan0', ifindex=7)), dict(version=True)]
        for update in cases:
            value = dict(self.state, **update)
            protocol.STATE.write_text(json.dumps(value))
            with self.assertRaisesRegex(protocol.ProtocolError, '^invalid-state$'):
                protocol.read_state()

    def test_unsafe_file_modes_symlinks_and_oversize_refuse(self):
        protocol.STATE.chmod(0o644)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_state()
        protocol.STATE.unlink()
        target = self.root / 'target'
        target.write_text(json.dumps(self.state)); target.chmod(0o600)
        protocol.STATE.symlink_to(target)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_state()
        protocol.STATE.unlink()
        protocol.STATE.write_bytes(b' ' * (protocol.LIMIT + 1)); protocol.STATE.chmod(0o600)
        with self.assertRaises(protocol.ProtocolError):
            protocol.read_state()

    def test_inactive_bad_cid_no_dns_and_unsafe_addresses_refuse(self):
        bad = []
        for at, value in ((0, 1), (2, 4), (3, 0), (4, 2)):
            item = bytearray(response()); item[at] = value; bad.append(bytes(item))
        bad += [response(dns=bytes(4)), response(address=bytes(4)),
                response(address=b'\x7f\x00\x00\x01'), response(dns=b'\xff' * 4)]
        for item in bad:
            value = dict(self.state, response_hex=item.hex())
            with self.assertRaises(protocol.ProtocolError):
                protocol.response_bytes(value)

    def test_unknown_or_boolean_lease_times_do_not_authorize(self):
        for updated in (True, float('inf'), -1):
            with self.assertRaises(protocol.ProtocolError):
                protocol.publish_lease(self.state, desired=True, awake=True, now=updated)
        with self.assertRaises(protocol.ProtocolError):
            protocol.publish_lease(self.state, desired=1, awake=True)
        protocol.publish_lease(self.state, desired=False, awake=False)
        self.assertFalse(protocol.read_lease(self.epoch)['desired'])

    def test_startup_cancel_needs_no_binding_but_cannot_forget_an_established_one(self):
        canceled = protocol.publish_state(self.epoch, 1, 'unavailable', 3, reason='canceled')
        self.assertIsNone(canceled['binding'])
        for phase in ('active', 'quiesce'):
            with self.assertRaises(protocol.ProtocolError):
                protocol.publish_state(self.epoch, 2, phase, 3,
                                       response=response() if phase == 'active' else None)
        protocol.STATE.unlink()
        protocol.publish_state(self.epoch, 0, 'active', 3, response=response())
        protocol.publish_state(self.epoch, 1, 'quiesce', 3, binding=self.binding)
        with self.assertRaises(protocol.ProtocolError):
            protocol.publish_state(self.epoch, 2, 'unavailable', 3, reason='canceled')

    def test_host_journal_is_private_bounded_and_validates_exact_dns_ownership(self):
        value = {key: self.state[key] for key in ('version', 'epoch', 'generation', 'cid', 'response_hex')}
        value.update(binding=self.binding, address_state='owned', route_state='owned',
                     dns=dict(kind='none'))
        protocol.publish_host(value)
        self.assertEqual(protocol.read_host(), value)
        self.assertEqual(protocol.OWNED.stat().st_mode & 0o777, 0o600)
        for update in (dict(binding=None), dict(address_state='unknown'),
                       dict(route_state='unknown'), dict(response_hex=response(cid=4).hex()),
                       dict(dns=dict(kind='file', state='owned', path='/etc/resolv.conf',
                                     original='nameserver 198.51.100.53\n', owned='unrelated'))):
            with self.assertRaisesRegex(protocol.ProtocolError, '^invalid-state$'):
                protocol.publish_host(dict(value, **update))
            self.assertEqual(protocol.read_host(), value)

    def test_non_regular_input_is_rejected_without_a_blocking_open(self):
        protocol.STATE.unlink()
        os.mkfifo(protocol.STATE, 0o600)
        with self.assertRaisesRegex(protocol.ProtocolError, '^invalid-state$'):
            protocol.read_state()


if __name__ == '__main__':
    unittest.main()
