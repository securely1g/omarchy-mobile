# SPDX-License-Identifier: MIT
"""Service guards/status around recovery; all files and processes are fakes."""
import env  # noqa: F401
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import paths
import service


class RecoveryServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for obj, name, value in ((paths, 'RUN', self.root),):
            p = patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.db = service.database(self.root / 'db')
        self.addCleanup(self.db.close)
        self.client = Mock()
        self.client.next_indication.return_value = None
        self.app = service.Service(self.client, self.db)
        self.guard = SimpleNamespace(ready=Mock(return_value=True), held=Mock(return_value=True))
        p = patch.object(service, 'new_recovery_guard', return_value=self.guard)
        self.factory = p.start()
        self.addCleanup(p.stop)

    def recover(self, **kwargs):
        attrs = dict(enabled=True, available=False, uncertain=False,
                     state='active', reason=None, guard_held=False, spent=False,
                     generation=0, tick=Mock(), observe=Mock(), invalidate=Mock())
        attrs.update(kwargs)
        self.app.recovery = SimpleNamespace(**attrs)
        return self.app.recovery

    def test_disabled_or_healthy_recovery_never_changes_guard(self):
        self.app.protect_recovery()
        self.recover(enabled=False, uncertain=True)
        self.app.protect_recovery()
        self.recover(available=True)
        self.app.protect_recovery()
        self.recover(state='unavailable', reason='owner-stopped')
        self.app.protect_recovery()
        self.factory.assert_not_called()

    def test_unknown_or_unavailable_starts_independent_guard_without_etc_write(self):
        for attrs in ({'uncertain': True}, {'state': 'unavailable'}):
            with self.subTest(attrs=attrs):
                self.app.recovery_guarded = False
                self.app.recovery_fail_guard = None
                self.app.recovery_guard_deadline = None
                self.factory.reset_mock()
                enable = self.root / 'enable'
                enable.touch()
                self.recover(**attrs)
                with patch.object(Path, 'unlink', side_effect=AssertionError('read-only /etc')):
                    self.app.protect_recovery()
                    self.app.protect_recovery()
                self.assertTrue(enable.exists())
                self.assertTrue(self.app.recovery_guarded)
                self.factory.assert_called_once_with()

    def test_held_independent_guard_needs_no_modem_unit_change(self):
        self.recover(uncertain=True, guard_held=True)
        self.app.protect_recovery()
        self.factory.assert_not_called()

    def test_claimed_start_without_real_block_lock_does_not_pass(self):
        self.recover(uncertain=True)
        self.guard.ready.return_value = False
        self.app.protect_recovery()
        self.assertFalse(self.app.recovery_guarded)
        self.app.recovery_guard_deadline = None
        with patch.object(service.time, 'monotonic', side_effect=[0, 4]):
            with self.assertRaisesRegex(RuntimeError, 'guard unavailable'):
                self.app.protect_recovery(wait=True)

    def test_nonready_guard_has_one_deadline_across_normal_ticks(self):
        self.recover(uncertain=True)
        self.guard.ready.return_value = False
        with patch.object(service.time, 'monotonic', side_effect=[10, 10, 11, 14]):
            self.app.protect_recovery()
            self.app.protect_recovery()
            with self.assertRaisesRegex(RuntimeError, 'guard unavailable'):
                self.app.protect_recovery()
        self.factory.assert_called_once()
        self.assertEqual(self.app.recovery_guard_deadline, 13)

    def test_unexpected_exit_before_controller_arms_still_holds_guard(self):
        self.app.recovery_requested = True
        self.app.protect_recovery(force=False)
        self.factory.assert_not_called()
        self.app.protect_recovery(force=True, wait=True)
        self.factory.assert_called_once_with()
        self.assertTrue(self.app.recovery_guarded)

    def test_data_flag_is_confirmed_availability_with_no_status_query(self):
        self.recover(available=False)
        for public in (False, True):
            self.assertFalse(self.app.status(public=public)['modem']['data'])
        self.app.recovery.available = True
        self.assertTrue(self.app.status()['modem']['data'])
        self.client.request.assert_not_called()

    def test_list_event_only_notifies_controller_and_publishes_safe_status(self):
        recovery = self.recover()
        packet = struct.pack('<BBHHH', 2, 0, 0x0604, 9, 0) + b'\0'
        self.app.event(packet)
        recovery.observe.assert_called_once_with(b'\0')
        recovery.tick.assert_not_called()
        self.client.request.assert_not_called()
        self.assertFalse(json.loads((self.root / 'state.json').read_text())['modem']['data'])

    def test_tick_availability_change_updates_public_file(self):
        recovery = self.recover(available=False)
        recovery.tick.side_effect = lambda **kwargs: setattr(recovery, 'available', True)
        self.app.advance_recovery(True)
        recovery.tick.assert_called_once_with(quiet=True)
        self.assertTrue(json.loads((self.root / 'state.json').read_text())['modem']['data'])

    def test_reset_and_sim_change_invalidate_without_reentrant_request(self):
        recovery = self.recover()
        for ident in (0x0804, 0x0210):
            self.app.event(struct.pack('<BBHHH', 2, 0, ident, 8, 0))
        self.assertEqual(recovery.invalidate.call_count, 2)
        self.client.request.assert_not_called()

    def test_off_then_on_in_one_pump_still_breaks_recovery_lifetime(self):
        recovery = self.recover(available=True)
        packets = [struct.pack('<BBHHHI', 2, 0, 0x0802, 12, 0, state) for state in (1, 10)]
        self.client.next_indication.side_effect = packets + [None]
        self.app.pump()
        self.assertEqual(self.app.radio, 'on')
        recovery.invalidate.assert_called_once()
        self.client.request.assert_not_called()

    def test_recovery_status_is_strict_cached_read_only(self):
        self.assertEqual(self.app.dispatch({'action': 'recovery-status'}),
                         dict(enabled=False, state='disabled', available=False))
        recovery = self.recover()
        result = self.app.dispatch({'action': 'recovery-status'})
        self.assertFalse(result['available'])
        self.assertFalse(result['spent'])
        self.assertEqual(result['generation'], 0)
        recovery.tick.assert_not_called()
        self.client.request.assert_not_called()
        with self.assertRaises(ValueError):
            self.app.dispatch({'action': 'recovery-status', 'command': 'anything'})


if __name__ == '__main__':
    unittest.main()
