# SPDX-License-Identifier: MIT
"""Actual daemon/host state machines share real atomic files over fake hardware."""
import env  # noqa: F401
import io
from contextlib import redirect_stdout
from unittest.mock import patch
import unittest

import data_call
import data_network
import network_lifecycle
import test_data_recovery as daemon_fixture
import test_network_host as host_fixture


class RecoveryRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.fixture = daemon_fixture.RecoveryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fake = host_fixture.Network()
        self.host = None
        stack = self.fixture.stack
        stack.enter_context(patch.object(network_lifecycle, 'OWNED', self.fixture.root / 'host-owned'))
        stack.enter_context(patch.object(data_network, 'INTERFACE', self.fixture.root / 'interface'))
        stack.enter_context(patch.object(data_network.paths, 'RUN', self.fixture.root))
        stack.enter_context(patch.object(data_network.time, 'monotonic', lambda: self.fixture.now))
        stack.enter_context(patch.object(data_network, 'run', self.fake.run))
        stack.enter_context(patch.object(data_network, 'transport_proof', self.fake.probe))
        stack.enter_context(patch.object(data_network, 'resolver_for', self.fake.resolver))
        stack.enter_context(patch.object(data_network, 'roaming_blocked', lambda: self.fake.blocked))
        stack.enter_context(redirect_stdout(io.StringIO()))

    def step(self):
        self.fake.now = self.fixture.now
        self.fixture.controller.tick(quiet=True)
        state = network_lifecycle.read_state()
        if state is not None:
            if self.host is None:
                self.host = data_network.ManagedNetwork(state)
                self.host.start()
            else:
                self.host.tick()
        self.fixture.now += .25

    def until(self, predicate, limit=1000):
        for _ in range(limit):
            if predicate():
                return
            self.step()
        self.fail('daemon/host transition did not finish: ' + self.fixture.controller.state)

    def arm(self):
        self.fixture.controller.arm()
        self.until(lambda: self.fixture.controller.available)
        self.assertEqual(network_lifecycle.read_ack()['generation'], 0)

    def test_real_quiesce_setup_changed_ip_dns_and_host_proof_roundtrip(self):
        self.arm()
        original_state = data_call.STATE.read_bytes()
        foreign = self.fixture.owner.items[2]
        self.fixture.loss()
        self.until(lambda: self.fixture.controller.state == 'setup')
        self.assertFalse(self.fake.addresses)
        self.assertFalse(any(r.get('dev') == 'rmnet2' for r in self.fake.routes))
        self.assertEqual(network_lifecycle.read_ack()['phase'], 'quiesced')
        self.until(lambda: self.fixture.controller.available)
        ack = network_lifecycle.read_ack()
        self.assertEqual((ack['generation'], ack['phase'], ack['binding']),
                         (2, 'applied', dict(dev='rmnet2', ifindex=7)))
        self.assertEqual([a['local'] for a in self.fake.addresses], ['192.0.2.11'])
        self.assertEqual(self.fake.resolvers[-1].servers, ['192.0.2.54'])
        self.assertTrue(any(r.get('dev') == 'wlan0' for r in self.fake.routes))
        self.assertEqual(data_call.STATE.read_bytes(), original_state)
        self.assertEqual(self.fixture.owner.items[2], foreign)
        self.assertEqual(len(self.fixture.setups()), 1)
        self.assertEqual(self.fixture.setups()[0][1], self.fixture.original.payload)
        self.assertFalse(self.fixture.guard.held())

    def test_failed_host_quiesce_never_authorizes_modem_setup(self):
        self.arm()
        self.fake.failure = lambda args: args[:3] == ('ip', 'addr', 'del')
        self.fixture.loss()
        self.until(lambda: self.fixture.controller.state == 'unavailable')
        self.assertEqual(self.fixture.setups(), [])
        self.assertFalse(self.fixture.controller.available)
        self.assertEqual(data_call.STATE.read_bytes(), self.fixture.state)

    def test_failed_active_helper_enters_unavailable_without_modem_setup(self):
        self.arm()
        self.host.fail('host-operation')
        self.until(lambda: self.fixture.controller.state == 'unavailable')
        self.assertFalse(self.fixture.controller.available)
        self.assertEqual(self.fixture.setups(), [])

    def test_live_sleep_lease_defers_recovery_without_claiming_data(self):
        self.arm()
        self.host.announced(True)
        for _ in range(20):
            self.step()
        self.assertEqual(self.fixture.controller.state, 'active')
        self.assertFalse(self.fixture.controller.available)
        self.assertEqual(self.fixture.setups(), [])

    def test_failed_new_transport_proof_never_advertises_data_or_retries_setup(self):
        self.arm()
        self.fixture.loss()
        self.until(lambda: self.fixture.controller.state == 'setup')
        self.fake.proof = False
        self.until(lambda: self.fixture.controller.state == 'unavailable')
        self.assertEqual(len(self.fixture.setups()), 1)
        self.assertTrue(self.fixture.controller.uncertain)
        self.assertTrue(self.fixture.guard.held())
        self.assertFalse(any(r.get('dev') == 'rmnet2' for r in self.fake.routes))
        for _ in range(20):
            self.step()
        self.assertEqual(len(self.fixture.setups()), 1)


if __name__ == '__main__':
    unittest.main()
