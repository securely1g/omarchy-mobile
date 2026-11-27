# SPDX-License-Identifier: MIT
import env  # noqa: F401
from contextlib import ExitStack, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import data_network as host
import network_lifecycle as protocol
from test_network_lifecycle import response


class Network:
    """A netlink/ip/resolver fixture; never runs a process or opens a device."""
    def __init__(self, link_local=False):
        self.up = False
        self.ifindex = 7
        self.addresses = []
        self.routes = [dict(dst='default', dev='wlan0', metric=600)]
        self.commands = []
        self.probes = []
        self.resolvers = []
        self.failure = lambda args: False
        self.proof = True
        self.on_proof = lambda: None
        self.blocked = False
        self.now = 100.0
        self.link_local = (dict(family='inet6', local='fe80::1', prefixlen=64,
                               scope='link', protocol='kernel_ll') if link_local else None)

    def run(self, *args):
        self.commands.append(args)
        if self.failure(args):
            raise RuntimeError('synthetic host operation failure')
        if args[:3] == ('ip', '-j', 'address'):
            return json.dumps([dict(ifindex=self.ifindex, flags=['UP'] if self.up else [],
                                    addr_info=list(self.addresses))]).encode()
        if args == ('ip', '-j', '-4', 'route', 'show', 'table', 'all'):
            return json.dumps(self.routes).encode()
        if args[:4] == ('ip', '-j', '-s', 'link'):
            return b'[{"stats64":{"rx":{"bytes":100},"tx":{"packets":10}}}]'
        if args[:4] == ('ip', 'link', 'set', 'dev'):
            self.up = args[-1] == 'up'
            if self.link_local:
                if self.up and self.link_local not in self.addresses:
                    self.addresses.append(dict(self.link_local))
                elif not self.up:
                    self.addresses = [a for a in self.addresses if a != self.link_local]
        elif args[:3] == ('ip', 'addr', 'add'):
            address = args[3].split('/')[0]
            if any(a['local'] == address for a in self.addresses):
                raise RuntimeError('duplicate address')
            self.addresses.append(dict(family='inet', local=address, prefixlen=32, scope='global'))
        elif args[:3] == ('ip', 'addr', 'del'):
            address = args[3].split('/')[0]
            self.addresses = [a for a in self.addresses if a['local'] != address]
        elif args[:4] == ('ip', 'route', 'add', 'default'):
            if any(r.get('dev') == 'rmnet2' and r.get('metric') == 700 for r in self.routes):
                raise RuntimeError('duplicate route')
            self.routes.append(dict(dst='default', dev='rmnet2', metric=700,
                                    prefsrc=args[args.index('src') + 1]))
        elif args[:4] == ('ip', 'route', 'del', 'default'):
            self.routes = [r for r in self.routes if not (r.get('dev') == 'rmnet2'
                                                         and r.get('metric') == 700)]
        return b''

    def probe(self, dev, address, allowed):
        self.probes.append((dev, address))
        self.on_proof()
        return allowed() and self.proof

    def resolver(self, servers, dev):
        fixture = self
        class Resolver:
            def __init__(self):
                self.servers = list(servers)
                self.released = False
            def update(self, cellular, new):
                fixture.run('dns-update')
                self.servers = list(new)
            def restore(self):
                fixture.run('dns-release')
                self.released = True
        result = Resolver()
        self.resolvers.append(result)
        return result


class HostTests(unittest.TestCase):
    network_factory = Network

    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        for name in ('STATE', 'ACK', 'LEASE', 'OWNED'):
            self.stack.enter_context(patch.object(protocol, name, self.root / name))
        self.stack.enter_context(patch.object(host, 'INTERFACE', self.root / 'interface'))
        self.stack.enter_context(patch.object(host.paths, 'RUN', self.root))
        self.fake = self.network_factory()
        self.stack.enter_context(patch.object(protocol, 'clock', lambda: self.fake.now))
        self.stack.enter_context(patch.object(host.time, 'monotonic', lambda: self.fake.now))
        self.stack.enter_context(patch.object(host, 'run', self.fake.run))
        self.stack.enter_context(patch.object(host, 'transport_proof', self.fake.probe))
        self.stack.enter_context(patch.object(host, 'resolver_for', self.fake.resolver))
        self.stack.enter_context(patch.object(host, 'roaming_blocked', lambda: self.fake.blocked))
        self.output = io.StringIO(); self.stack.enter_context(redirect_stdout(self.output))
        self.epoch = 'a' * 32
        state = protocol.publish_state(self.epoch, 0, 'active', 3, response=response())
        self.host = host.ManagedNetwork(state)
        self.assertTrue(self.host.start())
        self.binding = dict(dev='rmnet2', ifindex=7)
        self.assertEqual(protocol.read_ack()['phase'], 'applied')

    def quiesce(self):
        protocol.publish_state(self.epoch, 1, 'quiesce', 3, binding=self.binding)
        self.host.tick()

    def active(self, item=None):
        return protocol.publish_state(self.epoch, 2, 'active', 3, binding=self.binding,
                                      response=response() if item is None else item)

    def owned_routes(self):
        return [r for r in self.fake.routes if r.get('dev') == 'rmnet2']

    def test_quiesce_removes_only_owned_config_and_never_resurrects_without_wifi(self):
        self.quiesce()
        self.assertEqual(protocol.read_ack(self.epoch, 1)['phase'], 'quiesced')
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertTrue(self.fake.up)
        self.assertTrue(self.fake.resolvers[0].released)
        self.fake.routes = []
        self.host.announced(True); self.host.announced(False)
        self.fake.now += 400
        self.host.tick(); self.host.tick()
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(len(self.fake.probes), 1)

    def test_same_cid_changed_ip_dns_on_pinned_interface(self):
        self.quiesce()
        self.active(response(address=b'\xc0\x00\x02\x14', dns=b'\xc6\x33\x64\x35'))
        self.host.tick()
        self.assertEqual(protocol.read_ack(self.epoch, 2)['phase'], 'applied')
        self.assertEqual([a['local'] for a in self.fake.addresses], ['192.0.2.20'])
        self.assertEqual(self.owned_routes()[0]['prefsrc'], '192.0.2.20')
        self.assertEqual(self.fake.resolvers[-1].servers, ['198.51.100.53'])
        self.assertEqual(self.fake.probes, [('rmnet2', '192.0.2.10'), ('rmnet2', '192.0.2.20')])
        self.host.tick()
        self.assertEqual(len(self.fake.probes), 2)
        self.assertEqual(len(self.owned_routes()), 1)

    def test_same_configuration_reloads_without_duplicate_address_or_route(self):
        self.quiesce(); self.active(); self.host.tick(); self.host.tick()
        self.assertEqual(len(self.fake.addresses), 1)
        self.assertEqual(len(self.owned_routes()), 1)

    def test_changed_ifindex_is_never_reconfigured(self):
        self.quiesce(); self.active()
        self.fake.ifindex = 8
        self.fake.commands.clear(); self.host.tick()
        self.assertFalse(self.fake.addresses)
        self.assertFalse(any(c[:3] == ('ip', 'addr', 'add') for c in self.fake.commands))
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_foreign_address_or_conflicting_route_is_untouched(self):
        self.quiesce(); self.active()
        foreign = dict(family='inet', local='198.51.100.99', prefixlen=32)
        self.fake.addresses.append(foreign)
        self.host.tick()
        self.assertEqual(self.fake.addresses, [foreign])
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_foreign_metric700_route_is_never_replaced_or_deleted(self):
        self.quiesce(); self.active()
        foreign = dict(dst='default', dev='rmnet2', metric=700, prefsrc='198.51.100.99')
        self.fake.routes.append(foreign)
        self.host.tick()
        self.assertIn(foreign, self.fake.routes)
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_other_same_device_routes_block_address_cleanup_before_mutation(self):
        for route in (dict(dst='default', dev='rmnet2', metric=900),
                      dict(dst='198.51.100.0/24', dev='rmnet2', protocol='static'),
                      dict(dst='default', dev='rmnet2', metric=700, table=100,
                           prefsrc='192.0.2.10')):
            with self.subTest(route=route):
                self.fake.routes.append(route)
                self.fake.commands.clear()
                with self.assertRaisesRegex(host.HostFailure, 'host-conflict'):
                    self.host.quiesce()
                self.assertTrue(self.fake.addresses)
                self.assertIn(route, self.fake.routes)
                self.assertFalse(any(c[:2] in (('ip', 'addr'), ('ip', 'route'))
                                     for c in self.fake.commands))
                self.fake.routes.remove(route)

    def test_only_exact_connected_kernel_route_is_recognized(self):
        route = dict(dst='192.0.2.10/32', dev='rmnet2', protocol='kernel',
                     scope='link', prefsrc='192.0.2.10')
        self.fake.routes.append(route)
        self.assertTrue(self.host.inspect()[0])
        route['prefsrc'] = '198.51.100.99'
        with self.assertRaisesRegex(host.HostFailure, 'host-conflict'):
            self.host.inspect()

    def test_failed_quiesce_cannot_acknowledge_permission_to_setup(self):
        self.fake.failure = lambda a: a[:3] == ('ip', 'addr', 'del')
        self.quiesce()
        self.assertEqual(protocol.read_ack(self.epoch, 1)['phase'], 'failed')
        self.assertTrue(self.fake.addresses)
        self.assertEqual(len(self.fake.probes), 1)

    def test_dns_release_failure_never_acknowledges_quiescence(self):
        self.fake.failure = lambda a: a == ('dns-release',)
        self.quiesce()
        self.assertEqual(protocol.read_ack(self.epoch, 1)['phase'], 'failed')
        self.assertTrue(self.fake.addresses)

    def test_pending_resolved_constructor_is_reverted_before_cleanup_ack(self):
        self.quiesce(); self.active()
        resolver_path = Mock()
        resolver_path.exists.return_value = True
        resolver_path.resolve.return_value = '/run/systemd/resolve/stub-resolv.conf'
        self.fake.failure = lambda a: a[:2] == ('resolvectl', 'dns')
        with patch.object(host, 'RESOLVER', resolver_path), \
                patch.object(host, 'resolver_for', lambda servers, dev: host.ResolvedLink(servers, dev)):
            self.host.tick()
        self.assertIn(('resolvectl', 'revert', 'rmnet2'), self.fake.commands)
        self.assertEqual(protocol.read_host()['dns'], dict(kind='none'))
        self.assertFalse(self.fake.addresses)
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_pending_dns_revert_failure_preserves_evidence_and_blocks_cleanup(self):
        self.quiesce(); self.active()
        resolver_path = Mock()
        resolver_path.exists.return_value = True
        resolver_path.resolve.return_value = '/run/systemd/resolve/stub-resolv.conf'
        self.fake.failure = lambda a: a[0] == 'resolvectl'
        with patch.object(host, 'RESOLVER', resolver_path), \
                patch.object(host, 'resolver_for', lambda servers, dev: host.ResolvedLink(servers, dev)):
            self.host.tick()
        self.assertEqual(protocol.read_host()['dns'], dict(kind='resolved', state='releasing'))
        self.assertTrue(self.fake.addresses)
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_timed_out_address_add_does_not_guess_ownership_or_probe(self):
        self.quiesce(); self.active()
        def timeout_after_add(*args):
            result = self.fake.run(*args)
            if args[:3] == ('ip', 'addr', 'add'):
                raise subprocess.TimeoutExpired('ip', 20)
            return result
        with patch.object(host, 'run', timeout_after_add):
            self.host.tick(); self.host.tick()
        self.assertTrue(self.fake.addresses)
        self.assertEqual(protocol.read_host()['address_state'], 'adding')
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_failed_address_mutation_sends_no_new_probe_and_stays_unavailable(self):
        self.quiesce(); self.active()
        self.fake.failure = lambda a: a[:3] == ('ip', 'addr', 'add')
        self.host.tick(); self.host.tick()
        self.assertFalse(self.host.available)
        self.assertFalse(self.owned_routes())
        self.assertEqual(len(self.fake.probes), 1)

    def test_failed_route_add_does_not_repeat_proof_or_claim_applied(self):
        self.quiesce(); self.active()
        self.fake.failure = lambda a: a[:4] == ('ip', 'route', 'add', 'default')
        self.host.tick(); self.host.tick()
        self.assertEqual(protocol.read_ack(self.epoch, 2)['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 2)
        self.assertFalse(self.fake.addresses)

    def test_failed_transport_proof_keeps_route_absent_even_without_wifi(self):
        self.quiesce(); self.active(); self.fake.proof = False
        self.host.tick(); self.fake.routes = []; self.fake.now += 300; self.host.tick()
        self.assertFalse(self.owned_routes()); self.assertFalse(self.fake.addresses)
        self.assertEqual(protocol.read_ack()['reason'], 'proof-failed')
        self.assertEqual(len(self.fake.probes), 2)

    def test_sleep_and_resume_grace_defer_reload(self):
        self.quiesce(); self.host.announced(True); self.active(); self.host.tick()
        self.assertFalse(self.fake.addresses); self.assertEqual(len(self.fake.probes), 1)
        self.host.announced(False); self.fake.now += 29; self.host.tick()
        self.assertFalse(self.fake.addresses)
        self.fake.now += 1; self.host.tick()
        self.assertEqual(protocol.read_ack(self.epoch, 2)['phase'], 'applied')

    def test_roaming_defers_reload_without_host_mutation(self):
        self.quiesce(); self.active(); self.fake.blocked = True; self.host.tick()
        self.assertFalse(self.fake.addresses); self.assertEqual(len(self.fake.probes), 1)
        self.fake.blocked = False; self.host.tick()
        self.assertEqual(protocol.read_ack(self.epoch, 2)['phase'], 'applied')

    def test_sleep_during_proof_cancels_without_publishing_applied(self):
        self.quiesce(); self.active()
        self.fake.on_proof = lambda: self.host.announced(True)
        self.host.tick()
        self.assertFalse(self.owned_routes()); self.assertFalse(self.fake.addresses)
        self.assertEqual(protocol.read_ack(self.epoch, 2)['phase'], 'failed')

    def test_new_generation_during_proof_cannot_publish_old_applied_ack(self):
        self.quiesce(); self.active()
        self.fake.on_proof = lambda: protocol.publish_state(self.epoch, 3, 'unavailable', 3,
                                                            binding=self.binding, reason='canceled')
        self.host.tick(); self.host.tick()
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(protocol.read_ack()['generation'], 3)
        self.assertEqual(protocol.read_ack()['phase'], 'unavailable')

    def test_helper_restart_cannot_discover_again(self):
        other = host.ManagedNetwork(protocol.read_state())
        with patch.object(host, 'find_device') as discover:
            self.assertFalse(other.start())
        discover.assert_not_called()
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(protocol.read_ack()['binding'], self.binding)

    def test_restart_cleans_old_configuration_when_manifest_has_already_quiesced(self):
        protocol.publish_state(self.epoch, 1, 'quiesce', 3, binding=self.binding)
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(protocol.read_ack(self.epoch, 1)['binding'], self.binding)
        self.assertEqual(len(self.fake.probes), 1)

    def test_crash_after_new_address_before_ack_cleans_new_not_old_generation(self):
        self.quiesce(); self.active(response(address=b'\xc0\x00\x02\x14'))
        def crash():
            raise KeyboardInterrupt('simulated kill')
        self.fake.on_proof = crash
        with self.assertRaises(KeyboardInterrupt):
            self.host.tick()
        self.assertEqual(protocol.read_ack()['generation'], 1)
        self.assertEqual([a['local'] for a in self.fake.addresses], ['192.0.2.20'])
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(len(self.fake.probes), 2)
        self.assertEqual(protocol.read_ack(self.epoch, 2)['binding'], self.binding)

    def test_uncertain_add_retains_journal_and_binding_without_guessing_ownership(self):
        self.quiesce(); self.active(response(address=b'\xc0\x00\x02\x14'))
        original = self.host.journal
        def crash_before_commit(**changes):
            if changes.get('address_state') == 'owned':
                raise KeyboardInterrupt('simulated kill')
            return original(**changes)
        with patch.object(self.host, 'journal', crash_before_commit):
            with self.assertRaises(KeyboardInterrupt):
                self.host.tick()
        saved = protocol.OWNED.read_bytes()
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertTrue(self.fake.addresses)  # not proved ours: guard/reboot required
        self.assertEqual(protocol.OWNED.read_bytes(), saved)
        self.assertEqual(protocol.read_ack()['binding'], self.binding)
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(len(self.fake.probes), 1)

    def test_restart_preserves_foreign_configuration_and_journal(self):
        saved = protocol.OWNED.read_bytes()
        foreign = dict(dst='198.51.100.0/24', dev='rmnet2', protocol='static')
        self.fake.routes.append(foreign)
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertIn(foreign, self.fake.routes)
        self.assertTrue(self.fake.addresses)
        self.assertEqual(protocol.OWNED.read_bytes(), saved)
        self.assertEqual(protocol.read_ack()['binding'], self.binding)

    def test_restart_with_corrupt_journal_retains_validated_binding_but_changes_nothing(self):
        protocol.OWNED.write_text('{incomplete')
        saved = protocol.OWNED.read_bytes()
        self.fake.commands.clear()
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertEqual(protocol.read_ack()['binding'], self.binding)
        self.assertEqual(protocol.read_ack()['phase'], 'failed')
        self.assertEqual(protocol.OWNED.read_bytes(), saved)
        self.assertFalse(self.fake.commands)
        self.assertTrue(self.owned_routes()); self.assertTrue(self.fake.addresses)

    def test_restart_after_ifindex_change_never_touches_replacement_interface(self):
        self.fake.ifindex += 1
        saved = protocol.OWNED.read_bytes()
        self.fake.commands.clear()
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertEqual(protocol.read_host()['binding'], self.binding)
        self.assertEqual(protocol.OWNED.read_bytes(), saved)
        self.assertFalse(any(c[:2] in (('ip', 'addr'), ('ip', 'route'))
                             or c[0] == 'resolvectl' for c in self.fake.commands))
        self.assertEqual(len(self.fake.probes), 1)

    def test_stale_generation_or_changed_cid_never_reapplies(self):
        self.quiesce()
        for update, reason in ((dict(generation=3), 'stale-generation'),
                               (dict(cid=4, response_hex=response(cid=4).hex()), 'cid-changed')):
            value = dict(protocol.read_state(), phase='active', generation=2,
                         response_hex=response().hex(), **{})
            value.update(update)
            protocol.STATE.write_text(json.dumps(value))
            self.host.tick()
            self.assertEqual(protocol.read_ack()['reason'], reason)
            self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertEqual(len(self.fake.probes), 1)

    def prepare_file_dns(self):
        path = self.root / 'resolv.conf'
        path.write_text('nameserver 198.51.100.53\n')
        self.host.release_dns()
        self.stack.enter_context(patch.object(host, 'RESOLVER', path))
        self.stack.enter_context(patch.object(host, 'resolver_for', lambda *args: host.Resolver(path)))
        self.host.set_dns(True)
        self.assertIn('192.0.2.53', path.read_text())
        return path

    def test_restart_restores_only_exact_owned_global_dns_content(self):
        path = self.prepare_file_dns()
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertEqual(path.read_text(), 'nameserver 198.51.100.53\n')
        self.assertFalse(self.fake.addresses)

    def test_restart_restores_global_dns_from_the_previous_build(self):
        path = self.prepare_file_dns()
        journal = protocol.read_host()
        legacy = '# Omarchy Mobile cellular fallback (session only)\nnameserver 192.0.2.53\n'
        path.write_text(legacy)
        protocol.publish_host(dict(journal, dns=dict(journal['dns'], owned=legacy)))

        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertEqual(path.read_text(), 'nameserver 198.51.100.53\n')
        self.assertFalse(self.fake.addresses)

    def test_restart_does_not_overwrite_concurrent_wifi_dns(self):
        path = self.prepare_file_dns()
        path.write_text('nameserver 203.0.113.53\n')
        other = host.ManagedNetwork(protocol.read_state())
        self.assertFalse(other.start())
        self.assertEqual(path.read_text(), 'nameserver 203.0.113.53\n')
        self.assertFalse(self.fake.addresses)

    def test_manifest_disappearance_fails_closed(self):
        protocol.STATE.unlink(); self.host.tick()
        self.assertFalse(self.fake.addresses); self.assertFalse(self.owned_routes())
        self.assertFalse(self.host.available)

    def test_logs_do_not_include_addresses_or_response(self):
        self.quiesce(); self.active(); self.host.tick()
        text = self.output.getvalue()
        self.assertNotIn('192.0.2.', text)
        self.assertNotIn(response().hex(), text)


class LinkLocalHostTests(unittest.TestCase):
    """Linux may add link-local IPv6 as soon as discovery raises the link."""
    network_factory = staticmethod(lambda: Network(link_local=True))
    setUp = HostTests.setUp
    quiesce = HostTests.quiesce
    active = HostTests.active
    owned_routes = HostTests.owned_routes

    def test_link_local_survives_initial_apply_quiesce_changed_ip_reload_and_close(self):
        local = dict(self.fake.link_local)
        self.assertIn(local, self.fake.addresses)
        self.assertEqual(protocol.read_ack()['phase'], 'applied')
        self.quiesce()
        self.assertEqual(self.fake.addresses, [local])
        self.assertEqual(protocol.read_ack()['phase'], 'quiesced')
        self.active(response(address=b'\xc0\x00\x02\x14'))
        self.host.tick()
        self.assertIn(local, self.fake.addresses)
        self.assertEqual(protocol.read_ack()['phase'], 'applied')
        self.host.close()
        self.assertEqual(self.fake.addresses, [local])
        self.assertFalse(self.owned_routes())
        self.assertTrue(self.fake.up)
        self.assertFalse(any(c[:3] == ('ip', 'addr', 'flush')
                             or (c[:3] == ('ip', 'addr', 'del') and ':' in c[3])
                             or (c[:4] == ('ip', 'link', 'set', 'dev') and c[-1] == 'down')
                             for c in self.fake.commands))

    def test_restart_cleanup_preserves_link_local_and_never_discovers_again(self):
        other = host.ManagedNetwork(protocol.read_state())
        with patch.object(host, 'find_device') as discover:
            self.assertFalse(other.start())
        discover.assert_not_called()
        self.assertEqual(self.fake.addresses, [self.fake.link_local])
        self.assertFalse(self.owned_routes())
        self.assertEqual(len(self.fake.probes), 1)

    def test_link_local_without_kernel_protocol_is_not_assumed_automatic(self):
        local = next(a for a in self.fake.addresses if a['family'] == 'inet6')
        del local['protocol']
        self.fake.commands.clear()
        with self.assertRaisesRegex(host.HostFailure, 'host-conflict'):
            self.host.quiesce()
        self.assertEqual(len(self.fake.addresses), 2)
        self.assertFalse(any(c[:2] in (('ip', 'addr'), ('ip', 'route'))
                             for c in self.fake.commands))

    def test_link_local_accepts_explicit_proto_alias(self):
        local = next(a for a in self.fake.addresses if a['family'] == 'inet6')
        local['proto'] = local.pop('protocol')
        self.assertTrue(self.host.inspect()[2])
        self.quiesce()
        self.assertEqual(self.fake.addresses, [local])
        self.assertFalse(self.host.inspect()[2])

    def test_other_ipv6_or_wrong_link_local_metadata_blocks_before_mutation(self):
        for update in (dict(local='2001:db8::1', scope='global'),
                       dict(local='fd00::1', scope='global'),
                       dict(scope='global'), dict(prefixlen=128),
                       dict(protocol='static'), dict(protocol=None), dict(proto='static')):
            foreign = dict(self.fake.link_local, **update)
            with self.subTest(update=update):
                self.fake.addresses.append(foreign)
                self.fake.commands.clear()
                with self.assertRaisesRegex(host.HostFailure, 'host-conflict'):
                    self.host.quiesce()
                self.assertIn(foreign, self.fake.addresses)
                self.assertFalse(any(c[:2] in (('ip', 'addr'), ('ip', 'route'))
                                     or c[0] == 'resolvectl' for c in self.fake.commands))
                self.fake.addresses.remove(foreign)


class ProofTests(unittest.TestCase):
    def test_tcp_is_bound_before_connect_and_both_transports_required(self):
        connection = Mock()
        context = Mock()
        context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with patch.object(host.subprocess, 'run', return_value=Mock(returncode=0)), \
                patch.object(host.socket, 'socket', return_value=context):
            self.assertTrue(host.transport_proof('rmnet2', '192.0.2.10'))
        calls = connection.method_calls
        self.assertEqual([c[0] for c in calls], ['settimeout', 'setsockopt', 'bind', 'connect'])
        self.assertEqual(calls[1].args[-1], b'rmnet2\0')
        self.assertEqual(calls[2].args, (('192.0.2.10', 0),))

    def test_failed_binding_never_connects_or_uses_default_network(self):
        connection = Mock(); connection.setsockopt.side_effect = OSError('synthetic')
        context = Mock(); context.__enter__ = Mock(return_value=connection)
        context.__exit__ = Mock(return_value=False)
        with patch.object(host.subprocess, 'run', return_value=Mock(returncode=0)), \
                patch.object(host.socket, 'socket', return_value=context):
            self.assertFalse(host.transport_proof('rmnet2', '192.0.2.10'))
        connection.connect.assert_not_called()

    def test_failed_icmp_does_not_count_tcp_alone_as_proof(self):
        with patch.object(host.subprocess, 'run', return_value=Mock(returncode=1)) as ping, \
                patch.object(host.socket, 'socket') as tcp:
            self.assertFalse(host.transport_proof('rmnet2', '192.0.2.10'))
        self.assertEqual(ping.call_count, 2); tcp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
