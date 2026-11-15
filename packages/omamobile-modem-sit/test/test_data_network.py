# SPDX-License-Identifier: MIT
import env  # noqa: F401  (paths and sys.path first)
from contextlib import ExitStack, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import data_network
from data_network import Resolver, SleepHold, configuration, counters, guarded, looks_silent, sleep_signal

class ResolverTests(unittest.TestCase):
    def test_fallback_restoration_preserves_new_wifi_dns(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/'resolv'; p.write_text('wifi original\n'); r=Resolver(p)
            r.update(True,['192.0.2.53']); self.assertIn('192.0.2.53',p.read_text())
            r.update(False,[]); self.assertEqual(p.read_text(),'wifi original\n')
            r.update(True,['192.0.2.53']); p.write_text('wifi new\n')
            r.update(False,[]); self.assertEqual(p.read_text(),'wifi new\n')
    def test_rejects_inactive_or_wrong_bearer(self):
        for data in (b'',bytes(132),b'\0\0\2\1\3'+bytes(127)):
            with self.assertRaises(ValueError): configuration(data)

class RouteTests(unittest.TestCase):
    def test_only_logind_sleep_announcements_count(self):
        line = '{"type":"signal","member":"PrepareForSleep","payload":{"type":"b","data":[%s]}}'
        self.assertIs(sleep_signal(line % 'true'), True)
        self.assertIs(sleep_signal(line % 'false'), False)
        self.assertIsNone(sleep_signal(line.replace('PrepareForSleep', 'PrepareForShutdown') % 'true'))
        self.assertIsNone(sleep_signal('{"member":"PrepareForSleep","payload":{"data":["yes"]}}'))
        self.assertIsNone(sleep_signal('not json'))
        self.assertIsNone(sleep_signal('[]'))

    def test_the_route_goes_at_the_announcement_and_waits_for_wifi_after(self):
        hold = SleepHold(grace=10)
        self.assertFalse(hold.active)
        self.assertTrue(hold.announced(routed=True))     # remove it now
        self.assertFalse(hold.announced(routed=False))   # a second announcement changes nothing
        self.assertTrue(hold.active)
        self.assertFalse(hold.returns(others=True, now=0))   # not while asleep
        hold.over(now=100)
        self.assertTrue(hold.active)
        self.assertFalse(hold.returns(others=False, now=105))    # Wi-Fi not back, grace not over
        self.assertTrue(hold.returns(others=True, now=106))      # Wi-Fi leads out again
        self.assertFalse(hold.active)
        self.assertFalse(hold.returns(others=True, now=107))     # once

    def test_without_wifi_the_route_returns_after_the_grace(self):
        hold = SleepHold(grace=10)
        hold.announced(routed=True)
        hold.over(now=100)
        self.assertFalse(hold.returns(others=False, now=109.9))
        self.assertTrue(hold.returns(others=False, now=110))

    def test_a_route_that_was_not_there_is_not_brought_back(self):
        hold = SleepHold(grace=10)
        self.assertFalse(hold.announced(routed=False))   # removed earlier: silent bearer, roaming
        hold.over(now=100)
        self.assertFalse(hold.active)
        self.assertFalse(hold.returns(others=True, now=200))

    def test_a_sleep_during_the_wait_keeps_the_route_owed(self):
        hold = SleepHold(grace=10)
        hold.announced(routed=True)
        hold.over(now=100)
        self.assertFalse(hold.announced(routed=False))   # asleep again before it came back
        hold.over(now=200)
        self.assertTrue(hold.returns(others=True, now=201))

    def test_roaming_ends_the_wait(self):
        hold = SleepHold(grace=10)
        hold.announced(routed=True)
        hold.over(now=100, allowed=False)
        self.assertFalse(hold.active)
        hold.announced(routed=True)
        hold.over(now=300)
        hold.cancel()
        self.assertFalse(hold.returns(others=True, now=301))

    def test_counters_read_ip_json(self):
        stats=[{'stats64':{'rx':{'bytes':0,'packets':0},'tx':{'bytes':900,'packets':12}}}]
        self.assertEqual(counters(stats),(0,12))
    def test_sending_without_receiving_looks_silent(self):
        self.assertTrue(looks_silent(True,(0,10),(0,14)))
    def test_receiving_idle_or_unrouted_is_not_silent(self):
        self.assertFalse(looks_silent(True,(100,10),(900,40)))
        self.assertFalse(looks_silent(True,(0,10),(0,10)))
        self.assertFalse(looks_silent(False,(0,10),(0,40)))

class WatchTests(unittest.TestCase):
    def test_a_stalled_or_failed_ip_is_retried(self):
        def stalled(): raise subprocess.TimeoutExpired(('ip','route'),20)
        def failed(): raise RuntimeError('Cellular network operation failed: ip')
        def garbled(): raise ValueError('Expecting value')
        for step in (stalled,failed,garbled):
            self.assertIsNotNone(guarded(step))
        self.assertIsNone(guarded(lambda: None))
    def test_other_errors_still_end_the_service(self):
        def broken(): raise KeyError('dev')
        with self.assertRaises(KeyError): guarded(broken)


class ResumeWatchTests(unittest.TestCase):
    """Run the real watch loop with no network, device, bus or clock access."""

    def run_watch(self, frames, probes=(), failed_stats_at=(), failed_add_at=(), add_delay=0):
        commands, observed, probe_times = [], [], []
        state = dict(now=0, stats=(100, 10), blocked=False, routes=[
            dict(dev='rmnet2', metric=700), dict(dev='wlan0', metric=600)])
        pending = iter(frames)
        replies = iter(probes)
        done = False

        def run(*args):
            commands.append((state['now'], args))
            if args == ('ip', '-j', 'route', 'show', 'default'):
                return json.dumps(state['routes']).encode()
            if args == ('ip', '-j', '-s', 'link', 'show', 'dev', 'rmnet2'):
                if state['now'] in failed_stats_at:
                    raise subprocess.TimeoutExpired(args, 20)
                rx, tx = state['stats']
                return json.dumps([dict(stats64=dict(rx=dict(bytes=rx),
                                                     tx=dict(packets=tx)))]).encode()
            if args[:4] == ('ip', 'route', 'del', 'default'):
                state['routes'] = [r for r in state['routes']
                                   if not (r.get('dev') == 'rmnet2' and r.get('metric') == 700)]
            elif args[:4] == ('ip', 'route', 'add', 'default'):
                if state['now'] in failed_add_at:
                    raise RuntimeError('Cellular network operation failed: ip')
                state['routes'].append(dict(dev='rmnet2', metric=700))
                state['now'] += add_delay
            return b''

        def probe(dev):
            self.assertEqual(dev, 'rmnet2')  # never search/remap a live bearer
            probe_times.append(state['now'])
            result = next(replies)
            if isinstance(result, Exception):
                raise result
            return result

        class Sleeps:
            def wait(self, _):
                nonlocal done
                observed.append((state['now'], any(r.get('dev') == 'rmnet2'
                                                   for r in state['routes'])))
                frame = next(pending, None)
                if frame is None:
                    done = True
                    return []
                state.update({key: value for key, value in frame.items() if key != 'signals'})
                return frame.get('signals', [])

            def close(self):
                pass

        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            response = Path(temp) / 'response'
            response.write_bytes(b'\0\0\1')
            replacements = {
                'run': run, 'answers': probe, 'clear_stale': lambda: None,
                'wait_for_bearer': lambda _: None,
                'configuration': lambda _: ('192.0.2.10', ['192.0.2.53']),
                'find_device': lambda *_, **__: 'rmnet2',
                'resolver_for': lambda *_: Mock(), 'roaming_blocked': lambda: state['blocked'],
                'SleepWatch': Sleeps, 'RESPONSE': response,
                'INTERFACE': Path(temp) / 'interface',
            }
            for name, value in replacements.items():
                stack.enter_context(patch.object(data_network, name, value))
            stack.enter_context(patch.object(data_network.paths, 'RUN', Path(temp)))
            stack.enter_context(patch.object(data_network.cp, 'online', lambda: not done))
            stack.enter_context(patch.object(data_network.time, 'monotonic', lambda: state['now']))
            stack.enter_context(patch.object(data_network.signal, 'signal'))
            stack.enter_context(redirect_stdout(output))
            old_umask = os.umask(0o077)
            try:
                data_network.main()
            finally:
                os.umask(old_umask)
        return observed, probe_times, commands, output.getvalue()

    def test_resume_uses_a_fresh_interval_and_counter_baseline(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=29, signals=[True]),
            # The interrupted interval had TX but no RX. Wi-Fi is back, so
            # SleepHold returns the route immediately, ahead of its grace.
            dict(now=31, stats=(100, 20), signals=[False]),
            dict(now=31.5), dict(now=60.9), dict(now=61),
        ], probes=[False])
        self.assertTrue(all(routed for now, routed in observed if now >= 31))
        self.assertEqual(probes, [])

    def test_withdrawn_route_is_retried_without_displacing_wifi(self):
        observed, probes, commands, _ = self.run_watch([
            dict(now=30, stats=(100, 20)),  # failed health probe withdraws it
            dict(now=59.9), dict(now=60), dict(now=60.5),
        ], probes=[False, True])
        self.assertEqual(probes, [30, 60])
        self.assertIn((59.9, False), observed)
        self.assertIn((60.5, True), observed)
        self.assertTrue(all('wlan0' not in args for _, args in commands))

    def test_new_silent_traffic_after_the_grace_still_withdraws_the_route(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=29, signals=[True]),
            dict(now=31, stats=(100, 20), signals=[False]),
            dict(now=31.5, stats=(100, 21)), dict(now=60.9), dict(now=61),
        ], probes=[False])
        self.assertEqual(probes, [61])
        self.assertIn((60.9, True), observed)
        self.assertIn((61, False), observed)

    def test_slow_route_add_does_not_shorten_the_resume_health_interval(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=29, signals=[True]),
            dict(now=31, stats=(100, 20), signals=[False]),
            dict(now=51.5, stats=(100, 21)), dict(now=80.9), dict(now=81),
        ], probes=[False], add_delay=20)
        self.assertEqual(probes, [81])
        self.assertIn((80.9, True), observed)
        self.assertIn((81, False), observed)

    def test_failed_stats_read_does_not_lose_a_sleep_held_route(self):
        observed, probes, _, output = self.run_watch([
            dict(now=29, signals=[True]), dict(now=31, signals=[False]),
            dict(now=33), dict(now=64),
        ], failed_stats_at={31})
        self.assertEqual(probes, [])
        self.assertIn((31, False), observed)
        self.assertIn((33, True), observed)
        self.assertIn('Network checks work again', output)

    def test_rechecks_are_bounded_and_never_reinstate_an_unresponsive_bearer(self):
        observed, probes, _, output = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60), dict(now=120),
            dict(now=240), dict(now=500), dict(now=1000),
        ], probes=[False, False, False, False])
        self.assertEqual(probes, [30, 60, 120, 240])
        self.assertTrue(all(not routed for now, routed in observed if now >= 30))
        self.assertEqual(output.count('rechecks exhausted'), 1)

    def test_probe_errors_also_consume_the_bounded_retry_budget(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60), dict(now=61),
            dict(now=120), dict(now=121), dict(now=240), dict(now=241), dict(now=500),
        ], probes=[False] + [subprocess.TimeoutExpired(('ping',), 10)] * 3)
        self.assertEqual(probes, [30, 60, 120, 240])
        self.assertTrue(all(not routed for now, routed in observed if now >= 30))

    def test_initial_probe_error_does_not_retry_each_watch_pass(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=30.5, stats=(100, 21)),
            dict(now=31), dict(now=59.9), dict(now=60),
        ], probes=[subprocess.TimeoutExpired(('ping',), 10), True])
        self.assertEqual(probes, [30, 60])
        self.assertTrue(all(routed for _, routed in observed))

    def test_recheck_waits_through_sleep_and_a_full_interval_after_resume(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)),
            dict(now=59, signals=[True]), dict(now=60), dict(now=65),
            dict(now=70, signals=[False]), dict(now=99.9), dict(now=100),
        ], probes=[False, True])
        self.assertEqual(probes, [30, 100])
        self.assertIn((99.9, False), observed)
        self.assertIn((100, True), observed)

    def test_roaming_prohibition_cancels_pending_rechecks(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=59, blocked=True),
            dict(now=60), dict(now=100, blocked=False), dict(now=200),
        ], probes=[False])
        self.assertEqual(probes, [30])
        self.assertTrue(all(not routed for now, routed in observed if now >= 30))

    def test_no_wifi_still_restores_a_route_after_the_sleep_grace(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=29, signals=[True]),
            dict(now=31, stats=(100, 20), routes=[], signals=[False]),
            dict(now=40.9), dict(now=41), dict(now=71),
        ])
        self.assertEqual(probes, [])
        self.assertIn((40.9, False), observed)
        self.assertIn((41, True), observed)

    def test_a_successful_recheck_excludes_probe_traffic_from_the_next_interval(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60, stats=(100, 22)),
            dict(now=60.5), dict(now=90),
        ], probes=[False, True])
        self.assertEqual(probes, [30, 60])
        self.assertIn((90, True), observed)

    def test_failed_final_route_add_retries_only_ip_not_another_probe(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60), dict(now=120),
            dict(now=240), dict(now=242), dict(now=272),
        ], probes=[False, False, False, True], failed_add_at={240})
        self.assertEqual(probes, [30, 60, 120, 240])
        self.assertIn((240, False), observed)
        self.assertIn((242, True), observed)
        self.assertIn((272, True), observed)

    def test_pending_ip_restore_also_waits_through_sleep(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60),
            dict(now=61, signals=[True]), dict(now=62),
            dict(now=70, signals=[False]), dict(now=99.9), dict(now=100),
        ], probes=[False, True], failed_add_at={60})
        self.assertEqual(probes, [30, 60])
        self.assertIn((99.9, False), observed)
        self.assertIn((100, True), observed)

    def test_roaming_cancels_a_pending_ip_restore(self):
        observed, probes, _, _ = self.run_watch([
            dict(now=30, stats=(100, 20)), dict(now=60),
            dict(now=61, blocked=True), dict(now=100, blocked=False),
        ], probes=[False, True], failed_add_at={60})
        self.assertEqual(probes, [30, 60])
        self.assertTrue(all(not routed for now, routed in observed if now >= 30))


class DeviceTests(unittest.TestCase):
    def run_find(self, carrier, busy=(), cid=1, fail=None, stopped=lambda: False, probe=None):
        commands = []
        def run(*args):
            commands.append(args)
            if args[:3] == ('ip', '-j', 'address'):
                dev = args[-1]
                return ('[{"flags": ["%s"], "addr_info": [%s]}]' % (
                    'UP' if dev in busy else 'DOWN', '{}' if dev in busy else '')).encode()
            if fail and fail(args):
                raise RuntimeError('Cellular network operation failed: ip')
            return b''
        class Done:
            returncode = 0
        def undo(args, **kwargs):
            commands.append(tuple(args))
            return Done()
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(data_network, 'run', run), \
             patch.object(data_network.subprocess, 'run', undo), \
             patch.object(data_network.paths, 'RUN', Path(temp)), \
             patch.object(data_network, 'INTERFACE', Path(temp) / 'data-interface'):
            try:
                dev = data_network.find_device('192.0.2.10', cid, probe=probe or (lambda d: d == carrier),
                                               stopped=stopped)
            except (RuntimeError, InterruptedError):
                dev = None
            recorded = (Path(temp) / 'data-interface').read_text().strip() \
                if (Path(temp) / 'data-interface').exists() else None
        return dev, recorded, commands

    def test_stock_name_first_then_the_others(self):
        self.assertEqual(data_network.candidates(1)[:3], ['rmnet0', 'rmnet1', 'rmnet2'])
        self.assertEqual(data_network.candidates(2)[:2], ['rmnet1', 'rmnet0'])

    def test_the_device_that_answers_is_kept_and_recorded(self):
        dev, recorded, commands = self.run_find('rmnet1')
        self.assertEqual((dev, recorded), ('rmnet1', 'rmnet1'))
        # rmnet0 was tried and put back exactly; rmnet1 keeps address and route.
        self.assertIn(('ip', 'addr', 'del', '192.0.2.10/32', 'dev', 'rmnet0'), commands)
        self.assertIn(('ip', 'link', 'set', 'dev', 'rmnet0', 'down'), commands)
        self.assertIn(('ip', 'route', 'del', 'default', 'dev', 'rmnet0', 'metric', '700'), commands)
        self.assertNotIn(('ip', 'addr', 'del', '192.0.2.10/32', 'dev', 'rmnet1'), commands)
        self.assertEqual(commands[-1], ('ip', 'route', 'add', 'default', 'dev', 'rmnet1',
                                        'src', '192.0.2.10', 'metric', '700'))

    def test_a_configured_device_is_never_touched(self):
        dev, _, commands = self.run_find('rmnet2', busy=('rmnet0',))
        self.assertEqual(dev, 'rmnet2')
        self.assertFalse([c for c in commands if 'rmnet0' in c and c[:3] != ('ip', '-j', 'address')])

    def test_no_answer_anywhere_fails_and_leaves_nothing(self):
        dev, recorded, commands = self.run_find(None)
        self.assertEqual((dev, recorded), (None, None))
        ups = [c[-2] for c in commands if c[:4] == ('ip', 'link', 'set', 'dev') and c[-1] == 'up']
        downs = [c[-2] for c in commands if c[:4] == ('ip', 'link', 'set', 'dev') and c[-1] == 'down']
        self.assertEqual(ups, downs)

    def test_a_failed_step_puts_the_candidate_back(self):
        # The route add on rmnet0 fails (a stop kills the ip child): rmnet0 is
        # still put back, then rmnet1 is tried and kept.
        dev, recorded, commands = self.run_find(
            'rmnet1', fail=lambda a: a[:3] == ('ip', 'route', 'add') and 'rmnet0' in a)
        self.assertEqual((dev, recorded), ('rmnet1', 'rmnet1'))
        for step in (('ip', 'route', 'del', 'default', 'dev', 'rmnet0', 'metric', '700'),
                     ('ip', 'addr', 'del', '192.0.2.10/32', 'dev', 'rmnet0'),
                     ('ip', 'link', 'set', 'dev', 'rmnet0', 'down')):
            self.assertIn(step, commands)

    def test_a_stop_during_the_probe_puts_the_candidate_back_and_ends(self):
        state = {'stopped': False}
        def probe(dev):
            state['stopped'] = True      # SIGTERM arrives while rmnet0 is probed
            return True
        dev, recorded, commands = self.run_find(None, probe=probe, stopped=lambda: state['stopped'])
        self.assertEqual((dev, recorded), (None, None))
        self.assertIn(('ip', 'link', 'set', 'dev', 'rmnet0', 'down'), commands)
        self.assertIn(('ip', 'route', 'del', 'default', 'dev', 'rmnet0', 'metric', '700'), commands)
        # nothing after rmnet0 was touched
        self.assertFalse([c for c in commands if 'rmnet1' in c])

    def test_a_stale_record_is_cleared_at_start(self):
        commands = []
        class Done:
            returncode = 0
        def undo(args, **kwargs):
            commands.append(tuple(args))
            return Done()
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(data_network.subprocess, 'run', undo), \
             patch.object(data_network, 'INTERFACE', Path(temp) / 'data-interface'):
            (Path(temp) / 'data-interface').write_text('rmnet2\n')
            data_network.clear_stale()
            self.assertFalse((Path(temp) / 'data-interface').exists())
        self.assertEqual(commands, [('ip', 'route', 'del', 'default', 'dev', 'rmnet2', 'metric', '700'),
                                    ('ip', 'addr', 'flush', 'dev', 'rmnet2'),
                                    ('ip', 'link', 'set', 'dev', 'rmnet2', 'down')])


class RunDirTests(unittest.TestCase):
    def test_clients_keep_sitd_mode_0710(self):
        import paths as p
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp) / 'run'
            run.mkdir(mode=0o710); run.chmod(0o710)
            with patch.object(p, 'RUN', run):
                p.run_dir()
                self.assertEqual(run.stat().st_mode & 0o777, 0o710)
                run.chmod(0o777)          # anything wider is narrowed to 0710 at most
                p.run_dir()
                self.assertEqual(run.stat().st_mode & 0o777, 0o710)
            missing = Path(temp) / 'new'
            with patch.object(p, 'RUN', missing):
                p.run_dir()
                self.assertEqual(missing.stat().st_mode & 0o777, 0o700)

    def test_data_service_and_sit_client_do_not_use_private_dir_on_run(self):
        for name in ('data_network.py', 'sit.py'):
            text = (Path(__file__).resolve().parent.parent / 'lib' / name).read_text()
            self.assertNotIn('private_dir(paths.RUN)', text)
            self.assertNotIn('private_dir(RUN)', text)
