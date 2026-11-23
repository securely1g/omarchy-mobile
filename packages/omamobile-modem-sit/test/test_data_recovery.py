# SPDX-License-Identifier: MIT
"""Recovery state-machine fixtures: no modem, systemd or host network access."""
import env  # noqa: F401
from contextlib import ExitStack, redirect_stdout, redirect_stderr
import dataclasses
import io
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import data_call
import data_recovery as recovery
import network_lifecycle as lifecycle
import paths
import sit

PRIVATE = b'private-recovery-marker'
APN = 'internet.example'


def item(cid=3, address=10, dns=53, active=2):
    value = bytearray(132)
    struct.pack_into('<HBBB', value, 0, 0, cid, active, 3)
    value[5:9] = bytes([192, 0, 2, address])
    value[0x1a:0x1e] = bytes([192, 0, 2, dns])
    value[100:100 + len(PRIVATE)] = PRIVATE
    return bytes(value)


def listed(items):
    return bytes([len(items)]) + b''.join(items[cid] for cid in sorted(items))


class Guard:
    def __init__(self):
        self.present = True
        self.closed = False
    def ready(self):
        return self.present
    def held(self):
        return self.present and not self.closed
    def close(self):
        self.closed = True


class Owner:
    def __init__(self):
        self.items = {2: item(2, 20), 3: item()}
        self.new = item(address=11, dns=54, active=1)
        self.rat = 14
        self.radio = 10
        self.pending = {}
        self.sent = []
        self.block_setup = False
        self.setup_error = None
        self.cancelled = []
    def request(self, *args, **kwargs):
        raise AssertionError('recovery must never use a synchronous request')
    def begin_request(self, ident, payload=b'', timeout=8):
        sit.check(ident, payload=payload)
        if ident not in (0x0801, 0x0701, 0x0602, 0x0600):
            raise AssertionError('forbidden recovery request')
        if ident == 0x0600:
            if not recovery.SPENT.exists():
                raise AssertionError('mutation budget must be durable before send')
            value = self.new
        else:
            if payload or timeout != 5:
                raise AssertionError('read-only query must be empty and bounded')
            value = (struct.pack('<I', self.radio) if ident == 0x0801
                     else bytes([1, 0, 0, self.rat]) if ident == 0x0701
                     else listed(self.items))
        handle = object()
        self.pending[handle] = (ident, value)
        self.sent.append((ident, payload, timeout))
        return handle
    def poll_request(self, handle):
        ident, value = self.pending[handle]
        if ident == 0x0600 and self.block_setup:
            return None
        del self.pending[handle]
        if ident == 0x0600:
            if self.setup_error:
                raise self.setup_error
            self.items[3] = value
        return value
    def cancel_request(self, handle):
        self.pending.pop(handle, None)
        self.cancelled.append(handle)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for module, names in ((data_call, ('STATE', 'RESPONSE', 'MODEM_OWNED')),
                              (lifecycle, ('STATE', 'ACK', 'LEASE')), (recovery, ('SPENT',))):
            for name in names:
                self.stack.enter_context(patch.object(module, name, self.root / (module.__name__ + name)))
        self.now = 100.0
        self.stack.enter_context(patch.object(lifecycle, 'clock', lambda: self.now))
        self.owner = Owner()
        self.settings = paths.config()
        self.calls = []
        self.service = SimpleNamespace(client=self.owner, settings=self.settings,
            live=lambda: self.calls, radio='on', audio=None, release_unconfirmed=False)
        self.state = json.dumps(dict(cid=3, session=0)).encode()
        data_call.STATE.write_bytes(self.state)
        data_call.RESPONSE.write_bytes(item())
        data_call.paths(2)[0].write_text(json.dumps(dict(cid=2, session=0)))
        self.original = data_call.OriginalSetup(self.owner, 3,
            data_call.setup_payload(3, 14, 0, APN), self.state, item())
        self.stack.enter_context(patch.object(data_call, '_original_setup', self.original))
        self.guard = Guard()
        self.binding = dict(dev='rmnet2', ifindex=7)
        self.ack = True
        self.awake = True
        self.desired = True
        self.helper = True
        self.controller = self.make()

    def make(self, enabled=True):
        return recovery.Recovery(self.service, enabled=enabled, lifecycle=lifecycle,
            inhibitor_factory=lambda: self.guard, clock=lambda: self.now,
            settings_reader=lambda: self.settings)

    def tick(self, quiet=True):
        state = lifecycle.read_state()
        if state is not None and self.helper:
            lifecycle.publish_lease(state, desired=self.desired, awake=self.awake, binding=self.binding)
            if self.ack:
                phase = 'applied' if state['phase'] == 'active' else 'quiesced'
                if state['phase'] != 'unavailable':
                    lifecycle.publish_ack(state, phase, binding=self.binding)
        self.controller.tick(quiet=quiet)
        self.now += .1

    def until(self, state, limit=150):
        for _ in range(limit):
            if self.controller.state == state:
                return
            self.tick()
        self.fail('state not reached: ' + state + '; actual ' + self.controller.state)

    def arm(self):
        self.controller.arm()
        self.until('active')
        self.assertTrue(self.controller.available)

    def loss(self):
        self.owner.items.pop(3, None)
        self.controller.observe(listed(self.owner.items))

    def setups(self):
        return [call for call in self.owner.sent if call[0] == 0x0600]

    def test_default_off_has_no_files_requests_or_guard(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        controller = recovery.Recovery(self.service)
        with patch('data_recovery.subprocess.Popen', side_effect=AssertionError('process')):
            controller.arm(); controller.observe(b'\0'); controller.tick(quiet=True); controller.close()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        self.assertEqual(self.owner.sent, [])

    def test_complete_recovery_uses_only_original_setup_and_pinned_host_ack(self):
        self.arm(); self.loss()
        self.until('setup')
        self.assertEqual(self.setups(), [(0x0600, self.original.payload, 45)])
        self.assertTrue(self.guard.held())
        self.until('active')
        self.assertTrue(self.controller.available)
        self.assertFalse(self.controller.uncertain)
        self.assertTrue(self.guard.closed)
        self.assertEqual(data_call.STATE.read_bytes(), self.state)
        self.assertEqual(data_call.RESPONSE.read_bytes(), self.owner.new)
        self.assertEqual(lifecycle.read_state()['generation'], 2)
        self.assertEqual(lifecycle.read_state()['binding'], self.binding)
        self.assertEqual(recovery.SPENT.stat().st_mode & 0o777, 0o600)
        self.assertEqual({call[0] for call in self.owner.sent}, {0x0801, 0x0701, 0x0602, 0x0600})

    def test_stable_lte_ca_can_recover_without_rewriting_lte_access(self):
        self.arm(); self.loss(); self.owner.rat = 20
        self.until('setup')
        self.assertEqual(self.setups()[0][1], self.original.payload)
        self.assertEqual(self.setups()[0][1][1], 14)

    def test_supported_width_and_padding_do_not_define_pdn_identity(self):
        extended = bytearray(item() + bytes(160))
        extended[130] = 99
        extended[200] = 77
        self.assertEqual(recovery._identity(item()), recovery._identity(extended))
        self.owner.items[3] = bytes(extended)
        self.owner.items[2] += bytes(160)
        self.arm()
        self.assertTrue(self.controller.available)

    def test_known_dns_and_pcscf_changes_are_identity_changes(self):
        baseline = item(2, 20)
        self.assertNotEqual(recovery._identity(baseline), recovery._identity(item(2, 20, dns=54)))
        changed = bytearray(baseline)
        changed[0x42] = 1
        changed[0x43:0x47] = bytes([192, 0, 2, 60])
        self.assertNotEqual(recovery._identity(baseline), recovery._identity(changed))

    def test_off_one_is_rejected_and_observed_on_ten_is_accepted(self):
        self.owner.radio = 1
        self.controller.arm(); self.until('unavailable')
        self.assertFalse(self.controller.available)
        self.assertEqual(self.setups(), [])
        self.assertTrue(recovery.Recovery._radio_on(struct.pack('<I', 10)))
        self.assertTrue(recovery.Recovery._radio_on(struct.pack('<I', 2)))
        for value in (b'\x01', struct.pack('<I', 1), b'', struct.pack('<I', 4)):
            self.assertFalse(recovery.Recovery._radio_on(value))

    def test_no_absence_no_mutation_or_host_quiesce(self):
        self.arm(); self.controller.observe(listed(self.owner.items))
        for _ in range(20): self.tick()
        self.assertEqual(self.controller.state, 'active')
        self.assertTrue(self.controller.available)
        self.assertEqual(self.setups(), [])
        self.assertEqual(lifecycle.read_state()['generation'], 0)

    def test_present_bearer_remains_available_after_candidate_timeout(self):
        self.arm(); self.controller.observe(listed(self.owner.items))
        self.until('check-first'); self.until('active')
        # The investigation finished without a missing bearer. A healthy
        # helper lease must remain usable after that candidate's deadline,
        # including while reports keep the modem transport nonquiet.
        self.now += recovery.CANDIDATE_TIMEOUT + 1
        self.tick(quiet=False)
        self.assertEqual(self.controller.state, 'active')
        self.assertTrue(self.controller.available)
        self.assertEqual(self.setups(), [])
        self.assertFalse(recovery.SPENT.exists())
        self.assertEqual(lifecycle.read_state()['phase'], 'active')
        self.assertEqual(lifecycle.read_state()['generation'], 0)

    def test_new_foreign_or_changed_ims_context_refuses_without_setup(self):
        self.arm(); self.loss(); self.owner.items[7] = item(7, 70)
        self.until('unavailable')
        self.assertEqual(self.controller.reason, 'cid-changed')
        self.assertEqual(self.setups(), [])
        self.assertEqual(data_call.STATE.read_bytes(), self.state)

    def test_missing_ims_context_is_not_internet_only_loss(self):
        self.arm(); self.owner.items.clear(); self.controller.observe(b'\0')
        self.until('unavailable'); self.assertEqual(self.setups(), [])

    def test_unknown_rat_never_changes_original_request_or_sends_setup(self):
        self.arm(); self.loss(); self.owner.rat = 21
        self.until('unavailable'); self.assertEqual(self.setups(), [])

    def test_live_call_before_investigation_defers_then_pending_call_cancels(self):
        self.arm(); self.loss(); self.calls.append('ringing')
        for _ in range(5): self.tick()
        self.assertEqual(self.controller.state, 'active')
        self.assertEqual(self.setups(), [])
        self.calls.clear(); self.until('check-second')
        self.calls.append('ringing'); self.until('unavailable')
        self.assertEqual(self.setups(), [])

    def test_sleeping_or_stopped_helper_never_authorizes_mutation(self):
        self.arm(); self.loss(); self.awake = False
        for _ in range(10): self.tick()
        self.assertEqual(self.setups(), [])
        self.awake = True; self.until('wait-quiesce'); self.desired = False
        self.now += 31; self.until('unavailable')
        self.assertEqual(self.setups(), [])

    def test_wrong_binding_ack_refuses(self):
        self.arm(); self.loss(); self.until('wait-quiesce')
        self.binding = dict(dev='rmnet2', ifindex=8)
        self.until('unavailable'); self.assertEqual(self.setups(), [])

    def test_no_quiesced_ack_or_stale_lease_never_sends_setup(self):
        self.arm(); self.loss(); self.until('wait-quiesce')
        self.ack = False; self.helper = False; self.now += 31
        self.until('unavailable'); self.assertEqual(self.setups(), [])

    def test_pending_indication_barrier_and_nonquiet_tick_prevent_write(self):
        self.arm(); self.loss(); self.until('send')
        self.tick(quiet=False)
        self.assertEqual(self.setups(), [])
        self.controller.observe(listed(self.owner.items))
        self.until('unavailable')
        self.assertEqual(self.setups(), [])
        self.assertFalse(recovery.SPENT.exists())

    def test_deadline_is_enforced_without_a_quiet_transport(self):
        self.arm(); self.loss(); self.owner.block_setup = True; self.until('setup')
        self.now += 51
        self.controller.tick(quiet=False)
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertTrue(self.controller.uncertain)
        self.assertTrue(self.guard.held())
        self.assertEqual(len(self.setups()), 1)

    def test_call_cancels_pending_write_without_a_quiet_transport(self):
        self.arm(); self.loss(); self.owner.block_setup = True; self.until('setup')
        self.calls.append('ringing')
        self.controller.tick(quiet=False)
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertTrue(self.controller.uncertain)
        self.assertTrue(self.guard.held())
        self.assertEqual(len(self.setups()), 1)

    def test_old_absence_reply_cannot_override_newer_restoration_indication(self):
        self.arm(); self.loss(); self.until('check-first'); self.tick()
        self.owner.items[3] = item()
        self.controller.observe(listed(self.owner.items))
        self.tick()
        self.assertEqual(self.controller.state, 'check-first')
        self.until('active')
        self.assertEqual(self.setups(), [])
        self.assertTrue(self.controller.available)

    def test_changed_foreign_identity_and_malformed_list_stop_before_mutation(self):
        self.arm(); self.loss(); self.owner.items[2] = item(2, 21)
        self.until('unavailable')
        self.assertEqual(self.controller.reason, 'cid-changed')
        self.assertEqual(self.setups(), [])

    def test_malformed_list_stops_before_mutation(self):
        self.arm(); self.loss(); self.owner.items[2] = b'private'
        self.until('unavailable')
        self.assertEqual(self.setups(), [])

    def test_wrong_returned_cid_is_unknown_and_never_published(self):
        self.arm(); self.loss(); self.owner.new = item(4, 11)
        self.until('unavailable')
        self.assertEqual(len(self.setups()), 1)
        self.assertTrue(self.guard.held())
        self.assertEqual(data_call.RESPONSE.read_bytes(), item())

    def test_pending_guard_loss_is_detected_even_without_quiet(self):
        self.arm(); self.loss(); self.owner.block_setup = True; self.until('setup')
        self.guard.present = False
        self.controller.tick(quiet=False)
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertTrue(self.controller.uncertain)
        self.assertEqual(len(self.setups()), 1)

    def test_stale_active_lease_is_reflected_without_a_quiet_transport(self):
        self.arm(); self.helper = False; self.now += 6
        self.controller.tick(quiet=False)
        self.assertFalse(self.controller.available)

    def test_terminal_helper_failure_precedes_its_awake_false_lease(self):
        self.arm(); self.helper = False
        state = lifecycle.read_state()
        lifecycle.publish_lease(state, desired=True, awake=False, binding=self.binding)
        lifecycle.publish_ack(state, 'failed', binding=self.binding, reason='host-operation')
        self.controller.tick(quiet=False)
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertEqual(self.controller.reason, 'host-operation')
        self.assertEqual(lifecycle.read_state()['phase'], 'unavailable')
        self.assertEqual(self.setups(), [])

    def test_orderly_helper_stop_after_initial_ack_is_terminal(self):
        self.arm(); self.desired = False; self.tick()
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertEqual(self.controller.reason, 'helper-stopped')
        self.assertEqual(self.setups(), [])

    def test_dead_active_peer_gets_a_bounded_timeout(self):
        self.arm(); self.helper = False; self.now += 6
        self.controller.tick(quiet=False)
        self.now += 31; self.controller.tick(quiet=False)
        self.assertEqual(self.controller.state, 'unavailable')
        self.assertEqual(self.controller.reason, 'peer-timeout')
        self.assertEqual(self.setups(), [])

    def test_fresh_known_sleep_lease_defers_without_declaring_helper_failure(self):
        self.arm(); self.awake = False
        self.now += 60; self.tick()
        self.assertEqual(self.controller.state, 'active')
        self.assertFalse(self.controller.available)
        self.awake = True; self.tick()
        self.assertTrue(self.controller.available)
        self.assertEqual(self.setups(), [])

    def test_wrong_generation_ack_never_quiesces_the_current_generation(self):
        self.arm(); self.loss(); self.until('wait-quiesce'); self.ack = False
        self.tick()
        stale = dict(lifecycle.read_state(), generation=0)
        lifecycle.publish_ack(stale, 'quiesced', binding=self.binding)
        for _ in range(3): self.tick()
        self.assertEqual(self.controller.state, 'wait-quiesce')
        self.assertEqual(self.setups(), [])
        self.now += 31; self.until('unavailable')

    def test_roaming_and_legacy_allocated_session_cannot_arm(self):
        self.state = json.dumps(dict(cid=3, session=1)).encode()
        data_call.STATE.write_bytes(self.state)
        changed = dataclasses.replace(self.original, state=self.state)
        data_call._original_setup = changed
        self.controller.arm(); self.until('unavailable')
        self.assertEqual(self.setups(), [])

    def test_original_capture_is_the_successful_request_not_reconstructed_settings(self):
        data_call.STATE.unlink(); data_call.RESPONSE.unlink(); data_call.paths(2)[0].unlink()
        original = self.original
        sent = []
        def request(ident, payload=b'', **kwargs):
            sent.append((ident, payload))
            if ident == 0x0701: return bytes([1, 0, 0, 14])
            if ident == 0x0602: return b'\0'
            if ident == 0x0711: return b'\1'
            if ident == 0x0600:
                self.assertIsNone(data_call.original_setup(self.owner))
                return item()
            return b''
        with patch.object(data_call, 'INTERNET_CID', 3), \
                patch.object(data_call, 'SETTLE_LIMIT', 0), \
                patch.object(self.owner, 'request', side_effect=request), \
                patch('builtins.print'):
            data_call.activate(self.owner, APN, ip_type='ipv4v6')
        capture = data_call.original_setup(self.owner)
        self.assertIsNot(capture, original)
        self.assertEqual(capture.payload, next(p for ident, p in sent if ident == 0x0600))
        self.assertEqual(capture.state, data_call.STATE.read_bytes())
        self.assertEqual(capture.response, data_call.RESPONSE.read_bytes())

    def test_unknown_original_setup_does_not_leave_an_older_capture_armed(self):
        data_call.STATE.unlink(); data_call.RESPONSE.unlink(); data_call.paths(2)[0].unlink()
        def request(ident, payload=b'', **kwargs):
            if ident == 0x0701: return bytes([1, 0, 0, 14])
            if ident == 0x0602: return b'\0'
            if ident == 0x0711: return b'\1'
            if ident == 0x0600: raise TimeoutError('private')
            return b''
        with patch.object(data_call, 'INTERNET_CID', 3), \
                patch.object(data_call, 'SETTLE_LIMIT', 0), \
                patch.object(self.owner, 'request', side_effect=request), \
                patch('builtins.print'), self.assertRaises(TimeoutError):
            data_call.activate(self.owner, APN)
        self.assertIsNone(data_call.original_setup(self.owner))
        self.assertTrue(data_call.STATE.exists())

    def test_response_publisher_rejects_an_unexpected_cid_without_writing(self):
        with self.assertRaises(ValueError):
            data_call.publish_recovery_response(self.owner, self.original, item(4, 11))
        self.assertEqual(data_call.RESPONSE.read_bytes(), item())

    def test_changed_ownership_or_config_is_not_reconstructed(self):
        self.arm(); self.loss(); self.until('send')
        data_call.STATE.write_text(json.dumps(dict(cid=3, session=1)))
        self.until('unavailable'); self.assertEqual(self.setups(), [])

    def test_config_change_cancels_and_preserves_reservation(self):
        self.arm(); self.loss(); self.until('send')
        self.settings['network']['apn'] = 'another.example'
        self.until('unavailable'); self.assertEqual(self.setups(), [])
        self.assertEqual(data_call.STATE.read_bytes(), self.state)

    def test_timeout_after_send_keeps_spent_reservation_guard_and_host_unavailable(self):
        self.arm(); self.loss(); self.owner.setup_error = TimeoutError('private')
        self.until('unavailable')
        self.assertEqual(len(self.setups()), 1)
        self.assertTrue(self.controller.uncertain)
        self.assertTrue(self.guard.held())
        self.controller.close()
        self.assertTrue(self.guard.held())
        self.assertEqual(lifecycle.read_state()['phase'], 'unavailable')
        self.assertEqual(data_call.STATE.read_bytes(), self.state)
        self.assertEqual(data_call.RESPONSE.read_bytes(), item())

    def test_call_during_pending_setup_is_processed_and_never_retries_write(self):
        self.arm(); self.loss(); self.owner.block_setup = True; self.until('setup')
        self.calls.append('ringing')  # the normal service remains free to handle it
        self.until('unavailable')
        self.assertEqual(len(self.setups()), 1)
        self.assertTrue(self.guard.held())
        self.assertTrue(self.owner.cancelled)
        for _ in range(10): self.controller.tick(quiet=True)
        self.assertEqual(len(self.setups()), 1)

    def test_expected_post_setup_indication_requires_newer_final_get(self):
        self.arm(); self.loss(); self.until('final-list')
        self.tick()  # begin final GET
        self.controller.observe(listed(self.owner.items))
        self.tick()  # discard the old-generation reply, do not publish yet
        self.assertEqual(lifecycle.read_state()['phase'], 'quiesce')
        self.until('active')
        self.assertTrue(self.controller.available)
        self.assertEqual(len(self.setups()), 1)

    def test_foreign_change_after_setup_is_unknown_without_response_publication(self):
        self.arm(); self.loss(); self.until('final-list')
        self.owner.items[7] = item(7, 70)
        self.until('unavailable')
        self.assertTrue(self.guard.held())
        self.assertEqual(data_call.RESPONSE.read_bytes(), item())
        self.assertEqual(len(self.setups()), 1)

    def test_new_process_cannot_rearm_a_spent_boot(self):
        self.arm(); self.loss(); self.until('setup'); self.controller.close()
        self.controller = self.make(); self.controller.arm(); self.until('unavailable')
        self.assertTrue(self.controller.uncertain)
        self.assertEqual(len(self.setups()), 1)

    def test_no_second_attempt_after_successful_repair(self):
        self.arm(); self.loss(); self.until('setup'); self.until('active')
        self.loss(); self.until('unavailable')
        self.assertEqual(len(self.setups()), 1)

    def test_result_labels_and_original_repr_never_expose_private_values(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.arm(); self.loss(); self.until('setup'); self.until('active')
        text = json.dumps(dict(state=self.controller.state, reason=self.controller.reason,
                               available=self.controller.available)) + repr(self.original)
        self.assertEqual(out.getvalue() + err.getvalue(), '')
        for value in (PRIVATE.decode(), APN, PRIVATE.hex(), '192.0.2.10'):
            self.assertNotIn(value, text)

    def test_original_request_is_immutable_owner_bound_and_exact(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.original.payload = b'private'
        self.assertIsNone(data_call.original_setup(Owner()))
        with self.assertRaises(RuntimeError):
            data_call.recovery_payload(Owner(), self.original)
        self.assertEqual(data_call.recovery_payload(self.owner, self.original), self.original.payload)


class GuardTests(unittest.TestCase):
    def test_independent_unit_and_actual_root_logind_inhibitor_are_required(self):
        start = Mock(); start.poll.return_value = 0
        verify = Mock(); verify.poll.return_value = 0; verify.returncode = 0
        verify.stdout = io.BytesIO(json.dumps([dict(who='omamobile-data-recovery', mode='block',
                                                   what='sleep', uid=0, pid=123)]).encode())
        with patch('data_recovery.subprocess.Popen', side_effect=[start, verify, Mock()]) as process, \
                patch.object(recovery.SleepGuard, '_identity', return_value='start-time'):
            guard = recovery.SleepGuard()
            self.assertFalse(guard.ready())
            self.assertTrue(guard.ready())
            self.assertTrue(guard.held())
            guard.close()
        calls = [call.args[0] for call in process.call_args_list]
        self.assertEqual(calls[0][0], '/usr/bin/systemd-run')
        self.assertIn('--property=Restart=on-failure', calls[0])
        self.assertIn('--mode=block', calls[0])
        self.assertIn('--json=short', calls[1])
        self.assertEqual(calls[2], ['/usr/bin/systemctl', '--no-block', 'stop', recovery.GUARD_UNIT])

    def test_permanent_named_guard_matches_its_who_and_is_never_stopped(self):
        unit = 'omamobile-data-recovery-failsafe.service'
        who = 'omamobile-data-recovery-failsafe'
        start = Mock(); start.poll.return_value = 0
        verify = Mock(); verify.poll.return_value = 0; verify.returncode = 0
        verify.stdout = io.BytesIO(json.dumps([dict(who=who, mode='block', what='sleep',
                                                   uid=0, pid=123)]).encode())
        with patch('data_recovery.subprocess.Popen', side_effect=[start, verify]) as process, \
                patch.object(recovery.SleepGuard, '_identity', return_value='start-time'):
            guard = recovery.SleepGuard(unit=unit, who=who, permanent=True)
            self.assertFalse(guard.ready())
            self.assertTrue(guard.ready())
            guard.close()
            self.assertTrue(guard.held())
        self.assertEqual(process.call_count, 2)
        command = process.call_args_list[0].args[0]
        self.assertIn('--unit=' + unit, command)
        self.assertIn('--who=' + who, command)
        self.assertIn('--property=RefuseManualStop=yes', command)

    def test_permanent_close_terminates_only_its_verification_child(self):
        start = Mock(); start.poll.return_value = 0
        verify = Mock(); verify.poll.return_value = None
        with patch('data_recovery.subprocess.Popen', side_effect=[start, verify]) as process:
            guard = recovery.SleepGuard(permanent=True)
            self.assertFalse(guard.ready())
            guard.close()
        verify.terminate.assert_called_once_with()
        self.assertEqual(process.call_count, 2)

    def test_named_guard_pid_identity_requires_its_exact_system_unit(self):
        unit = 'omamobile-data-recovery-failsafe.service'
        with patch('data_recovery.subprocess.Popen'):
            guard = recovery.SleepGuard(unit=unit)
        stat = '123 (inhibitor) ' + ' '.join(['S'] + ['0'] * 18 + ['start-time'])
        def read(path, *args, **kwargs):
            return '0::/system.slice/' + unit + '\n' if path.name == 'cgroup' else stat
        with patch.object(Path, 'read_text', autospec=True, side_effect=read):
            self.assertEqual(guard._identity(123), 'start-time')
        with patch.object(Path, 'read_text', return_value='0::/system.slice/' + recovery.GUARD_UNIT):
            with self.assertRaises(recovery.Unsafe):
                guard._identity(123)


if __name__ == '__main__':
    unittest.main()
