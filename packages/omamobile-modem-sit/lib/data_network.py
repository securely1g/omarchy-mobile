#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""omamobile-sit-data: the internet bearer (CID 1) as a fallback behind Wi-Fi.

CPIF's rmnet devices are raw-IP links that NetworkManager doesn't manage
(the package marks rmnet* unmanaged). This owns only the bearer's rmnet
device: its /32 address, a metric-700 default route (Wi-Fi's default is 600,
so Wi-Fi wins while it is up) and the carrier's DNS while it is the only way
out. All state and rollback records stay in RAM; nothing here is logged with
an address.

Which rmnet carries the bearer: stock's RIL names it rmnet<CID - 1>
(PdpContext's "%s%d" with the RIL socket's ifprefix and ifstart), and that is
tried first. On a network that attaches on another APN than the internet one,
the attach bearer held rmnet0 and the CID 1 internet bearer came out on
rmnet1 (cheetah, 2026-11-02), so the rest are tried after it: the device
that answers a ping with the bearer's address is the one kept, and its name
is recorded in RAM (data-interface) for the bearer's release.

The carrier's DNS is used only while the bearer is the only way out. A bearer
that sends but receives nothing, and then answers no ping either, loses its
default route. A bounded set of probes on that same device can restore it
behind Wi-Fi; it also gets it back as soon as nothing else is left. Otherwise a
dead bearer's route plus its DNS can outlive a short Wi-Fi outage, make
NetworkManager's connectivity check fail through it and keep the phone
offline with Wi-Fi up.

Around a system sleep the default route is taken away (SleepHold): at
logind's announcement NetworkManager takes Wi-Fi down, and a route through
the bearer would carry everything that had been talking over Wi-Fi, bring
the modem's link up and make the kernel refuse the sleep.
"""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import subprocess
import time

import cp
import paths
import network_lifecycle as lifecycle
from data_call import RESPONSE

RESOLVER = Path('/etc/resolv.conf')
INTERFACE = paths.RUN / 'data-interface'
# rmnet0-rmnet7 are tried; CPIF creates 30, a phone uses a handful.
CANDIDATES = 8
HEALTH_INTERVAL = 30
# A budget per withdrawal: a transient loss must not withdraw the fallback
# for the rest of the boot, but a broken bearer is not polled forever.
RECHECK_DELAYS = (30, 60, 120)


def run(*args):
    p = subprocess.run(args, capture_output=True, timeout=20)
    if p.returncode:
        raise RuntimeError('Cellular network operation failed: ' + args[0])
    return p.stdout


def configuration(data):
    if len(data) < 132:
        raise ValueError('Short internet bearer response')
    status, cid, active, pdp = struct.unpack_from('<HBBB', data)
    if status or cid == 2 or not 1 <= cid <= 15 or active not in (1, 2) or pdp not in (1, 3):
        raise ValueError('An active IPv4 internet bearer is required')
    addr = ipaddress.IPv4Address(data[5:9])
    dns = list(dict.fromkeys(str(ipaddress.IPv4Address(data[i:i+4])) for i in (0x1a, 0x2e) if any(data[i:i+4])))
    if addr.is_unspecified or addr.is_multicast or not dns:
        raise ValueError('Missing internet address or carrier DNS')
    return str(addr), dns


def preserved_link_local(address):
    """Recognize the IPv6 link-local Linux can add when the link comes up.

    It is not our configuration: never count it as an owned address or
    remove it during IPv4 quiescence. Any other IPv6 configuration remains
    a collision, including link-local addresses without kernel provenance.
    """
    protocols = [address[key] for key in ('protocol', 'proto') if key in address]
    if address.get('family') != 'inet6' or address.get('scope') != 'link' \
            or address.get('prefixlen') != 64 \
            or not isinstance(address.get('local'), str) \
            or not protocols or any(value != 'kernel_ll' for value in protocols):
        return False
    try:
        return ipaddress.IPv6Address(address['local']).is_link_local
    except ValueError:
        return False


def counters(stats):
    """(received bytes, sent packets) from `ip -j -s link` output for the device."""
    link = stats[0]['stats64']
    return link['rx']['bytes'], link['tx']['packets']


def looks_silent(routed, before, after):
    """The routed bearer sent packets but received nothing since the last
    check. Not proof: a few router solicitations get no answer on a live one."""
    return routed and after[1] > before[1] and after[0] == before[0]


def guarded(step):
    """One pass of the route watch; the error of a failed or stalled `ip`, or
    None. Such a failure is retried: when this service exits the cellular
    fallback is gone until someone restarts it, and one stalled `ip route`
    must not cost hours without cellular."""
    try:
        step()
    except (subprocess.SubprocessError, RuntimeError, ValueError) as error:
        return error
    return None


def answers(dev):
    """Whether the bearer carries anything: a ping out through its device."""
    for target in ('1.1.1.1', '8.8.8.8'):
        p = subprocess.run(['ping', '-n', '-q', '-c', '1', '-W', '3', '-I', dev, target],
                           capture_output=True, timeout=10)
        if p.returncode == 0:
            return True
    return False


def transport_proof(dev, address, allowed=lambda: True):
    """One bounded ICMP check and one TCP connect, both on the pinned link.

    No DNS, HTTP response body or new tool dependency. A failed bind never
    falls back to the default interface. Both transports must answer.
    """
    icmp = False
    for target in ('1.1.1.1', '8.8.8.8'):
        if not allowed():
            return False
        try:
            result = subprocess.run(['ping', '-n', '-q', '-c', '1', '-W', '3',
                                     '-I', dev, target], capture_output=True, timeout=5)
            icmp = result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass
        if icmp:
            break
    if not icmp or not allowed():
        return False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                                  dev.encode('ascii') + b'\0')
            connection.bind((address, 0))
            connection.connect(('1.1.1.1', 443))
    except OSError:
        return False
    return allowed()


class Resolver:
    """The carrier's DNS in /etc/resolv.conf while cellular is the only way
    out; the previous file comes back unless something (NetworkManager) has
    written a newer one meanwhile."""
    def __init__(self, path):
        self.path = path.resolve()
        self.original = None
        self.owned = None

    def update(self, cellular, servers):
        if cellular:
            content = '# Omamobile cellular fallback (session only)\n' + ''.join('nameserver ' + s + '\n' for s in servers)
            current = self.path.read_text()
            if self.owned is None or current != self.owned:
                self.original = current
            if current != content:
                self.path.write_text(content)
            self.owned = content
        else:
            self.restore()

    def restore(self):
        if self.owned is not None:
            if self.path.read_text() == self.owned:
                self.path.write_text(self.original)
            self.owned = None


class ResolvedLink:
    """The same with systemd-resolved: the device's DNS servers are set once and
    the link is the default DNS route only while cellular is the only way out."""
    def __init__(self, servers, dev):
        self.dev = dev
        run('resolvectl', 'dns', dev, *servers)
        self.servers = tuple(servers)
        self.cellular = None

    def update(self, cellular, servers):
        if tuple(servers) != self.servers:
            run('resolvectl', 'dns', self.dev, *servers)
            self.servers = tuple(servers)
        if cellular != self.cellular:
            run('resolvectl', 'default-route', self.dev, 'yes' if cellular else 'no')
            self.cellular = cellular

    def restore(self):
        subprocess.run(['resolvectl', 'revert', self.dev], capture_output=True, timeout=20)

    def release(self):
        """Acknowledged cleanup for the cooperative lifecycle."""
        run('resolvectl', 'revert', self.dev)
        self.servers = None
        self.cellular = None


def resolver_for(servers, dev):
    target = str(RESOLVER.resolve()) if RESOLVER.exists() else ''
    if target.startswith('/run/systemd/resolve/'):
        return ResolvedLink(servers, dev)
    return Resolver(RESOLVER)


def roaming_blocked(config=None, state=None):
    """Data roaming is off ([data] roaming = no) and the network says the
    phone is roaming: then rmnet0 gets no default route. Read on every pass,
    so the Mobile network page's switch applies without a restart."""
    try:
        if paths.config(config)['data'].getboolean('roaming', True):
            return False
    except (ValueError, OSError):
        return False
    try:
        status = json.loads(Path(state or paths.RUN / 'state.json').read_text())
    except (OSError, ValueError):
        return False
    return (status.get('modem') or {}).get('registration') == 'roaming'


def candidates(cid):
    """rmnet<CID - 1> (stock's name for the bearer) first, then the others."""
    first = cid - 1
    return [f'rmnet{first}'] + [f'rmnet{i}' for i in range(CANDIDATES) if i != first]


def unused(dev):
    """The device exists and nobody has configured it (down, no address)."""
    try:
        info = json.loads(run('ip', '-j', 'address', 'show', 'dev', dev))[0]
    except (RuntimeError, ValueError, IndexError):
        return False
    return 'UP' not in info['flags'] and not info['addr_info']


def put_back(dev, address=None):
    """Undo a candidate's configuration, every step on its own and none
    fatal: whatever was set before a failure or a stop goes. Only devices
    this service records (data-interface) or is probing get here, and rmnet
    devices carry nothing but this service's configuration."""
    steps = [('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')]
    steps.append(('ip', 'addr', 'del', address + '/32', 'dev', dev) if address
                 else ('ip', 'addr', 'flush', 'dev', dev))
    steps.append(('ip', 'link', 'set', 'dev', dev, 'down'))
    for step in steps:
        try:
            subprocess.run(step, capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


def clear_stale():
    """A device recorded by a run that ended without its cleanup (killed, or
    stopped before 0.3.12 while probing): put it back before anything else."""
    try:
        dev = INTERFACE.read_text().strip()
    except OSError:
        return
    if dev.startswith('rmnet') and dev[5:].isdigit():
        put_back(dev)
        print('Removed a configuration left on', dev, 'by an earlier run', flush=True)
    INTERFACE.unlink(missing_ok=True)


def find_device(address, cid, probe=None, stopped=lambda: False, eligible=lambda dev: True):
    """Bring each unused candidate up with the bearer's /32 and the metric-700
    default route until one carries it (ping -I binds to the device, so the
    route through it is used even with Wi-Fi's better one present); that one
    keeps its address and route. Every other one is put back as it was, also
    when a step fails or the service is stopped in the middle (the record in
    data-interface is written before the device is touched, so a run that is
    killed outright is cleaned up by the next start)."""
    probe = probe or answers
    for dev in candidates(cid):
        if stopped():
            break
        if not unused(dev) or not eligible(dev):
            continue
        paths.run_dir()
        INTERFACE.write_text(dev + '\n')
        kept = False
        try:
            run('ip', 'link', 'set', 'dev', dev, 'up')
            run('ip', 'addr', 'add', address + '/32', 'dev', dev)
            run('ip', 'route', 'add', 'default', 'dev', dev, 'src', address, 'metric', '700')
            try:
                kept = probe(dev) and not stopped()
            except subprocess.SubprocessError:
                kept = False
        except RuntimeError:
            kept = False
        finally:
            if not kept:
                put_back(dev, address)
                INTERFACE.unlink(missing_ok=True)
        if kept:
            print('Bearer CID', cid, 'carried by', dev, flush=True)
            return dev
    if stopped():
        raise InterruptedError('Stopped while looking for the bearer device')
    raise RuntimeError('No rmnet device carries the internet bearer (no ping answered)')


def wait_for_bearer(seconds):
    deadline = time.monotonic() + seconds
    while not RESPONSE.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError('No internet bearer: omamobile-sitd has not set one up')
        time.sleep(1)


# How long after a sleep the cellular default route waits for Wi-Fi.
RETURN_GRACE = 10
SLEEP_MATCH = ("type='signal',interface='org.freedesktop.login1.Manager',"
               "member='PrepareForSleep'")


def sleep_signal(line):
    """True or False for a logind PrepareForSleep line of busctl's JSON
    monitor (a sleep is starting, or is over), None for anything else."""
    try:
        message = json.loads(line)
    except ValueError:
        return None
    if not isinstance(message, dict) or message.get('member') != 'PrepareForSleep':
        return None
    data = (message.get('payload') or {}).get('data')
    if isinstance(data, list) and len(data) == 1 and isinstance(data[0], bool):
        return data[0]
    return None


class SleepWatch:
    """logind's sleep announcements, read without blocking. Without busctl
    nothing is heard, and the route simply stays as it was."""

    def __init__(self):
        self.buffer = b''
        try:
            self.process = subprocess.Popen(
                ['busctl', 'monitor', '--system', '--json=short', '--match', SLEEP_MATCH],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            os.set_blocking(self.process.stdout.fileno(), False)
        except OSError:
            self.process = None

    def wait(self, seconds):
        """Sleep up to seconds; return the announcements heard, in order."""
        if not self.process:
            time.sleep(seconds)
            return []
        heard = []
        ready, _, _ = select.select([self.process.stdout], [], [], seconds)
        if ready:
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:   # the monitor ended: go on without it
                self.close()
                return heard
            self.buffer += chunk
            *lines, self.buffer = self.buffer.split(b'\n')
            for line in lines:
                state = sleep_signal(line.decode(errors='replace'))
                if state is not None:
                    heard.append(state)
        return heard

    def close(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None


class SleepHold:
    """The cellular default route around a system sleep.

    When the system goes to sleep NetworkManager takes Wi-Fi down first, and
    the bearer's default route is then the only one: whatever was talking
    over Wi-Fi sends through the bearer in that moment, the modem's link
    comes up, and the kernel refuses the sleep because of it. So the route
    goes at logind's announcement. After the sleep it waits for something
    else to lead out again, or for RETURN_GRACE without that: put back at
    once, it carried a few seconds of traffic at every wake, and the answers
    to that traffic ended the next sleeps early.
    """

    def __init__(self, grace=RETURN_GRACE):
        self.grace = grace
        self.sleeping = False
        self.held = False       # the route is ours to bring back
        self.back_at = None     # when it returns if nothing else leads out

    @property
    def active(self):
        """True while the route's presence is this class's business."""
        return self.sleeping or self.back_at is not None

    def announced(self, routed):
        """A sleep is starting. True when the route has to go now."""
        if self.sleeping:
            return False
        self.sleeping = True
        # Still waiting to return after the last sleep counts as held.
        self.held = routed or self.back_at is not None
        self.back_at = None
        return routed

    def over(self, now, allowed=True):
        """The sleep is over; allowed is False when roaming forbids data."""
        if not self.sleeping:
            return
        self.sleeping = False
        if self.held and allowed:
            self.back_at = now + self.grace
        self.held = False

    def returns(self, others, now):
        """True once: the route comes back now (others: another default
        route exists)."""
        if self.sleeping or self.back_at is None:
            return False
        if others or now >= self.back_at:
            self.back_at = None
            return True
        return False

    def cancel(self):
        """Roaming took the route away for good: nothing to bring back."""
        self.held = False
        self.back_at = None


class HostFailure(RuntimeError):
    """Only fixed lifecycle reason labels may leave the host transaction."""


class Superseded(HostFailure):
    pass


class ManagedNetwork:
    """Cooperative host configuration; never owns a modem channel.

    Only start() can discover a device. All later operations are confined
    to the saved interface index, CID, and configuration this object added.
    An unsuccessful generation cannot enter the ordinary fallback watch.
    """
    def __init__(self, state, drain=lambda: None):
        lifecycle.response_bytes(state)  # complete schema validation
        self.state = state
        self.binding = None
        self.address = None
        self.dns = []
        self.resolver = None
        self.available = False
        self.quiesced = False
        self.failed = False
        self.uncertain = False
        self.hold = SleepHold()
        self.awake_at = 0
        self.seen = None
        self.check_at = 0
        self.retry_at = None
        self.retries = 0
        self.drain = drain
        self.owned = None

    def journal(self, **changes):
        if self.owned is None:
            raise HostFailure('host-operation')
        value = dict(self.owned, generation=self.state['generation'], **changes)
        if value == self.owned:
            return
        self.owned = lifecycle.publish_host(value)

    def claim(self, response_hex, *, address_state='none', route_state='none'):
        value = {key: self.state[key] for key in ('version', 'epoch', 'generation', 'cid')}
        value.update(binding=self.binding, response_hex=response_hex,
                     address_state=address_state, route_state=route_state, dns={'kind': 'none'})
        self.owned = lifecycle.publish_host(value)

    @property
    def dev(self):
        return self.binding['dev']

    def awake(self):
        return not self.hold.sleeping and time.monotonic() >= self.awake_at

    def lease(self, desired=True):
        lifecycle.publish_lease(self.state, desired=desired,
                                awake=self.awake() and not self.failed,
                                binding=self.binding)

    def current(self):
        self.drain()
        if lifecycle.read_state() != self.state:
            raise Superseded('stale-generation')

    def permitted(self):
        self.current()
        return self.awake() and not roaming_blocked()

    def inspect(self):
        """Read ownership collisions before touching the pinned device."""
        try:
            links = json.loads(run('ip', '-j', 'address', 'show', 'dev', self.dev))
            if len(links) != 1 or links[0]['ifindex'] != self.binding['ifindex'] \
                    or 'UP' not in links[0]['flags']:
                raise HostFailure('interface-changed')
            addresses = [a for a in links[0]['addr_info'] if not preserved_link_local(a)]
            if any(a.get('family') != 'inet' or a.get('local') != self.address
                   or a.get('prefixlen') != 32 for a in addresses):
                raise HostFailure('host-conflict')
            routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
            defaults = [r for r in routes if r.get('dst') == 'default'
                        and r.get('table', 'main') in ('main', 254)]
            candidates = [r for r in defaults if r.get('dev') == self.dev and r.get('metric') == 700]
            if len(candidates) > 1 or any(self.address is None or r.get('prefsrc') != self.address
                                          or r.get('gateway') for r in candidates):
                raise HostFailure('host-conflict')
            for route in routes:
                if route.get('dev') != self.dev or route in candidates:
                    continue
                # The kernel may create a connected /32 with the address.
                # Any other route makes address ownership ambiguous, even
                # when its default-route metric differs from ours.
                connected = (self.address is not None
                             and route.get('dst') in (self.address, self.address + '/32')
                             and route.get('protocol') == 'kernel'
                             and route.get('prefsrc') == self.address
                             and not route.get('gateway')
                             and route.get('metric', 0) == 0
                             and ((route.get('scope') == 'link'
                                   and route.get('table', 'main') in ('main', 254))
                                  or (route.get('scope') == 'host'
                                      and route.get('table') in ('local', 255)
                                      and route.get('type') == 'local')))
                if not connected:
                    raise HostFailure('host-conflict')
            return bool(candidates), [r for r in defaults if r not in candidates], bool(addresses)
        except (KeyError, IndexError, TypeError, ValueError):
            raise HostFailure('host-conflict') from None

    def mutation(self, *args):
        try:
            return run(*args)
        except subprocess.TimeoutExpired:
            # A timed-out ip/resolver command may have changed the host.
            # Never call that quiesced or blindly claim/delete its result.
            self.uncertain = True
            raise HostFailure('host-operation') from None

    def drop_route(self):
        routed, _, _ = self.inspect()
        if routed:
            self.journal(route_state='removing')
            self.mutation('ip', 'route', 'del', 'default', 'dev', self.dev,
                          'src', self.address, 'metric', '700')
        self.journal(route_state='none')

    def set_dns(self, cellular):
        if self.resolver is None:
            target = str(RESOLVER.resolve()) if RESOLVER.exists() else ''
            if target.startswith('/run/systemd/resolve/'):
                self.journal(dns=dict(kind='resolved', state='setting'))
            self.resolver = resolver_for(self.dns, self.dev)
        if isinstance(self.resolver, Resolver):
            if not cellular:
                self.release_dns()
                return
            current = self.resolver.path.read_text()
            original = (current if self.resolver.owned is None or current != self.resolver.owned
                        else self.resolver.original)
            content = '# Omarchy Mobile cellular fallback (session only)\n' + ''.join(
                'nameserver ' + server + '\n' for server in self.dns)
            saved = dict(kind='file', state='setting', path=str(self.resolver.path),
                         original=original, owned=content)
            if self.owned['dns'] != dict(saved, state='owned'):
                self.journal(dns=saved)
            self.resolver.update(True, self.dns)
            self.journal(dns=dict(saved, state='owned'))
        else:
            if (self.owned['dns'] == dict(kind='resolved', state='owned')
                    and getattr(self.resolver, 'servers', None) == tuple(self.dns)
                    and getattr(self.resolver, 'cellular', None) is cellular):
                return
            self.journal(dns=dict(kind='resolved', state='setting'))
            self.resolver.update(cellular, self.dns)
            self.journal(dns=dict(kind='resolved', state='owned'))

    def saved_resolver(self):
        """Reconstruct only the cleanup handle, without installing DNS."""
        dns = self.owned['dns']
        if dns['kind'] == 'file':
            if str(RESOLVER.resolve()) != dns['path']:
                raise HostFailure('host-conflict')
            self.resolver = Resolver(RESOLVER)
            self.resolver.original, self.resolver.owned = dns['original'], dns['owned']
        elif dns['kind'] == 'resolved':
            self.resolver = ResolvedLink.__new__(ResolvedLink)
            self.resolver.dev = self.dev
            self.resolver.servers = tuple(self.dns)
            self.resolver.cellular = None

    def release_dns(self):
        # The constructor may have set link DNS before raising. Its pending
        # journal is enough for a checked revert, never for a new DNS set.
        if self.resolver is None and self.owned['dns']['kind'] != 'none':
            self.saved_resolver()
        if self.resolver is not None:
            saved = self.owned['dns']
            if saved['kind'] != 'none':
                self.journal(dns=dict(saved, state='releasing'))
            try:
                if isinstance(self.resolver, ResolvedLink):
                    self.resolver.release()
                else:
                    self.resolver.restore()
            except subprocess.TimeoutExpired:
                self.uncertain = True
                raise HostFailure('host-operation') from None
            self.resolver = None
        self.journal(dns=dict(kind='none'))

    def quiesce(self):
        self.available = False
        self.retry_at = None
        self.hold.cancel()
        if self.binding is None or self.uncertain:
            raise HostFailure('host-operation')
        self.drop_route()
        self.release_dns()
        _, _, addressed = self.inspect()
        if addressed:
            self.journal(address_state='removing')
            self.mutation('ip', 'addr', 'del', self.address + '/32', 'dev', self.dev)
        self.journal(address_state='none')
        self.address = None
        self.dns = []
        # Read back the cleanup; no ACK if a route/address remains or an
        # unrelated configuration appeared during the operation.
        routed, _, addressed = self.inspect()
        if routed or addressed:
            raise HostFailure('host-operation')
        self.quiesced = True

    def fail(self, reason):
        self.failed = True
        self.available = False
        self.retry_at = None
        self.hold.cancel()
        try:
            if self.binding is not None:
                self.quiesce()
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        lifecycle.publish_ack(self.state, 'failed', binding=self.binding, reason=reason)
        self.lease()
        print('Cellular host configuration unavailable:', reason, flush=True)

    def interval(self):
        self.seen = counters(json.loads(run('ip', '-j', '-s', 'link', 'show', 'dev', self.dev)))
        self.check_at = time.monotonic() + HEALTH_INTERVAL

    def add_route(self):
        self.current()
        routed, _, addressed = self.inspect()
        if not addressed or not self.permitted():
            raise HostFailure('canceled')
        if not routed:
            self.journal(route_state='adding')
            self.mutation('ip', 'route', 'add', 'default', 'dev', self.dev,
                          'src', self.address, 'metric', '700')
        self.journal(route_state='owned')
        self.current()
        if not self.inspect()[0]:
            raise HostFailure('host-operation')
        self.interval()

    def start(self):
        # A killed helper leaves these records behind deliberately. Never
        # turn a restart into another scan of potentially occupied rmnet's.
        if self.state['generation'] != 0 or self.state['phase'] != 'active' \
                or self.state['binding'] is not None \
                or any(os.path.lexists(p) for p in (lifecycle.ACK, lifecycle.LEASE, lifecycle.OWNED, INTERFACE)):
            try:
                self.cleanup_previous()
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                self.uncertain = True
            self.fail('initialization-failed')
            return False
        self.lease()
        address, dns = lifecycle.configuration(self.state)
        def eligible(dev):
            routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'table', 'all'))
            if any(route.get('dev') == dev for route in routes):
                return False
            if self.binding is not None:
                # Legacy discovery's failed candidate cleanup must actually
                # have completed before its reservation can be replaced.
                info = json.loads(run('ip', '-j', 'address', 'show', 'dev', self.dev))[0]
                if info['addr_info'] or any(route.get('dev') == self.dev for route in routes):
                    raise HostFailure('host-operation')
            info = json.loads(run('ip', '-j', 'address', 'show', 'dev', dev))[0]
            self.binding = dict(dev=dev, ifindex=info['ifindex'])
            self.claim(self.state['response_hex'], address_state='adding', route_state='adding')
            return True
        dev = find_device(address, self.state['cid'],
                          probe=lambda d: transport_proof(d, address, self.permitted),
                          stopped=lambda: not self.permitted(), eligible=eligible)
        info = json.loads(run('ip', '-j', 'address', 'show', 'dev', dev))[0]
        self.binding = dict(dev=dev, ifindex=info['ifindex'])
        self.address, self.dns = address, dns
        self.journal(address_state='owned', route_state='owned')
        self.current()
        self.inspect()
        self.set_dns(not self.inspect()[1])
        self.interval()
        self.available = True
        lifecycle.publish_ack(self.state, 'applied', binding=self.binding)
        self.lease()
        return True

    def cleanup_previous(self):
        """A restarted process may clean proven ownership, never resume it.

        The journal survives an ACK gap and a changed-IP generation. An
        unfinished address add is ambiguous: retain evidence and the saved
        binding, fail unavailable, and leave recovery to a guarded reboot.
        """
        # Preserve a separately validated binding even if the ownership
        # journal is damaged. It authorizes no cleanup without that journal.
        self.binding = self.state['binding']
        ack, lease = lifecycle.read_ack(), lifecycle.read_lease(max_age=None)
        if (ack and lease and ack['epoch'] == lease['epoch'] == self.state['epoch']
                and ack['cid'] == lease['cid'] == self.state['cid']
                and ack['binding'] == lease['binding']
                and self.binding in (None, ack['binding'])):
            self.binding = ack['binding']
        saved = lifecycle.read_host()
        if saved is None:
            self.uncertain = True
            return
        self.binding = dict(saved['binding'])
        if (saved['epoch'] != self.state['epoch'] or saved['cid'] != self.state['cid']
                or saved['generation'] > self.state['generation']
                or self.state['binding'] not in (None, saved['binding'])):
            raise HostFailure('binding-mismatch')
        self.owned = saved
        active = {key: saved[key] for key in ('version', 'epoch', 'generation', 'cid', 'binding', 'response_hex')}
        active.update(phase='active', reason=None)
        address, self.dns = lifecycle.configuration(active)
        if saved['address_state'] == 'adding':
            self.uncertain = True
            return
        self.address = address if saved['address_state'] in ('owned', 'removing') else None
        self.saved_resolver()
        self.quiesce()

    def accept(self, state):
        if state['epoch'] != self.state['epoch']:
            raise HostFailure('epoch-changed')
        if state['cid'] != self.state['cid']:
            raise HostFailure('cid-changed')
        if state['binding'] != self.binding:
            raise HostFailure('binding-mismatch')
        if state['generation'] != self.state['generation'] + 1:
            raise HostFailure('stale-generation')
        if state['phase'] == 'active' and (self.state['phase'] != 'quiesce' or not self.quiesced):
            raise HostFailure('not-quiesced')
        self.state = state
        self.available = False
        self.failed = False
        self.retry_at = None
        self.hold.cancel()

    def apply(self):
        if not self.permitted():
            return  # no host mutation or proof during sleep/roaming
        if not self.quiesced or self.address is not None:
            raise HostFailure('not-quiesced')
        self.inspect()
        address, dns = lifecycle.configuration(self.state)
        self.current()
        self.claim(self.state['response_hex'], address_state='adding')
        self.mutation('ip', 'addr', 'add', address + '/32', 'dev', self.dev)
        self.address, self.dns = address, dns
        self.journal(address_state='owned')
        self.quiesced = False
        self.set_dns(False)
        self.current()
        self.inspect()
        if not self.permitted():
            raise HostFailure('canceled')
        if not transport_proof(self.dev, address, self.permitted):
            raise HostFailure('proof-failed')
        self.add_route()
        self.set_dns(not self.inspect()[1])
        self.current()
        self.available = True
        lifecycle.publish_ack(self.state, 'applied', binding=self.binding)
        print('Cellular host configuration applied after bound transport proof', flush=True)

    def watch(self):
        # Reached only for the current, successfully applied generation.
        self.current()
        routed, others, _ = self.inspect()
        if roaming_blocked():
            self.drop_route()
            self.release_dns()
            self.retry_at = None
            self.hold.cancel()
            return
        self.set_dns(routed and not others)
        if self.hold.active:
            if self.hold.returns(bool(others), time.monotonic()):
                if not self.awake():
                    self.hold.back_at = self.awake_at
                else:
                    self.add_route()
            return
        if not self.awake():
            return
        if not routed and not others:
            self.add_route()
            self.retry_at = None
        elif not routed and self.retry_at is not None and time.monotonic() >= self.retry_at:
            self.retries += 1
            self.retry_at = (time.monotonic() + RECHECK_DELAYS[self.retries]
                             if self.retries < len(RECHECK_DELAYS) else None)
            if transport_proof(self.dev, self.address, self.permitted):
                self.add_route()
                self.retry_at = None
        elif routed and time.monotonic() >= self.check_at:
            before = self.seen
            self.interval()
            if looks_silent(True, before, self.seen) \
                    and not transport_proof(self.dev, self.address, self.permitted):
                self.current()
                self.drop_route()
                self.retries = 0
                self.retry_at = time.monotonic() + RECHECK_DELAYS[0]

    def tick(self):
        try:
            state = lifecycle.read_state()
            if state is None:
                raise HostFailure('invalid-state')
            if state != self.state:
                self.accept(state)
            if self.failed:
                return
            if self.state['phase'] in ('quiesce', 'unavailable'):
                if not self.quiesced:
                    self.quiesce()
                self.current()
                phase = 'quiesced' if self.state['phase'] == 'quiesce' else 'unavailable'
                lifecycle.publish_ack(self.state, phase, binding=self.binding)
            elif not self.available:
                self.apply()
            else:
                self.watch()
        except Superseded:
            # A new generation cannot inherit a partly applied old one.
            self.available = False
            try:
                self.quiesce()
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
                self.fail('host-operation')
        except HostFailure as error:
            self.fail(str(error))
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            self.fail('host-operation')
        finally:
            self.lease()

    def announced(self, sleeping):
        if sleeping:
            routed = self.inspect()[0] if self.binding is not None else False
            if self.hold.announced(routed and self.available):
                self.drop_route()
        else:
            self.hold.over(time.monotonic(), self.available and not roaming_blocked())
            self.awake_at = time.monotonic() + HEALTH_INTERVAL
            if self.retry_at is not None:
                self.retry_at = max(self.retry_at, self.awake_at)
        self.lease()

    def close(self):
        try:
            if self.binding is not None:
                self.quiesce()
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            lifecycle.publish_ack(self.state, 'failed', binding=self.binding,
                                  reason='host-operation')
        else:
            lifecycle.publish_ack(self.state, 'unavailable', binding=self.binding,
                                  reason='helper-stopped')
        finally:
            self.lease(desired=False)


def managed_main(state, stopped):
    sleeps = SleepWatch()
    network = ManagedNetwork(state)

    def drain():
        for sleeping in sleeps.wait(0):
            network.announced(sleeping)
    network.drain = drain
    try:
        if not network.start():
            return
        while not stopped() and cp.online():
            drain()
            network.tick()
            for sleeping in sleeps.wait(.5):
                network.announced(sleeping)
    finally:
        network.close()
        sleeps.close()


def main():
    os.umask(0o077)
    lock = os.open(paths.RUN / 'data-network.lock', os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    managed_stop = False

    def stop_managed(*_):
        nonlocal managed_stop
        managed_stop = True
    signal.signal(signal.SIGTERM, stop_managed)
    signal.signal(signal.SIGINT, stop_managed)
    managed = paths.config()['control'].getboolean('recover_data', False)
    state = lifecycle.read_state()
    if managed or state is not None:
        try:
            deadline = time.monotonic() + 180
            while state is None and not managed_stop and time.monotonic() < deadline:
                time.sleep(.5)
                state = lifecycle.read_state()
            if state is not None and not managed_stop:
                managed_main(state, lambda: managed_stop)
        finally:
            os.close(lock)
        return
    clear_stale()
    wait_for_bearer(60)
    data = RESPONSE.read_bytes()
    address, dns = configuration(data)
    stopping = False
    addressed = False
    dev = None

    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    resolver = None
    sleeps = None
    try:
        dev = find_device(address, data[2], stopped=lambda: stopping)
        addressed = True
        resolver = resolver_for(dns, dev)
        if roaming_blocked():
            run('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')
            print('Roaming with data roaming off; the cellular default route is not set', flush=True)
        print('Cellular fallback ready; Wi-Fi remains preferred', flush=True)
        last = None
        seen = counters(json.loads(run('ip', '-j', '-s', 'link', 'show', 'dev', dev)))
        check_at = time.monotonic() + HEALTH_INTERVAL
        retry_at = None
        retries = 0
        restore_at = None
        hold = SleepHold()

        def fresh_interval():
            nonlocal seen, check_at
            # No traffic from before the sleep (or while its route was
            # withheld) belongs to the next health interval.
            seen = counters(json.loads(run('ip', '-j', '-s', 'link', 'show', 'dev', dev)))
            check_at = time.monotonic() + HEALTH_INTERVAL

        def restore_answered(routed):
            nonlocal restore_at, check_at
            fresh_interval()
            if not routed:
                run('ip', 'route', 'add', 'default', 'dev', dev, 'src', address, 'metric', '700')
            check_at = time.monotonic() + HEALTH_INTERVAL
            restore_at = None
            print('Cellular bearer answered; its fallback route is back', flush=True)

        def watch():
            nonlocal last, seen, check_at, retry_at, retries, restore_at
            routes = json.loads(run('ip', '-j', 'route', 'show', 'default'))
            routed = any(r.get('dev') == dev for r in routes)
            others = [r for r in routes if r.get('dev') != dev]
            if roaming_blocked():
                if routed:
                    run('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')
                    print('Roaming with data roaming off; the cellular default route is removed', flush=True)
                resolver.update(False, dns)
                hold.cancel()
                retry_at = None
                restore_at = None
                last = None
                return
            # With Wi-Fi up but rated limited, the carrier's DNS would keep
            # NetworkManager's own check failing and Wi-Fi penalised.
            cellular = routed and not others
            resolver.update(cellular, dns)
            if cellular != last:
                print('Default internet path', 'cellular' if cellular else 'Wi-Fi/other', flush=True)
                last = cellular
            if hold.active:
                if hold.returns(bool(others), time.monotonic()):
                    try:
                        fresh_interval()
                        if not routed:
                            run('ip', 'route', 'add', 'default', 'dev', dev, 'src', address, 'metric', '700')
                        check_at = time.monotonic() + HEALTH_INTERVAL
                        restore_at = None
                    except (subprocess.SubprocessError, RuntimeError, ValueError):
                        # The hold is not fulfilled until both operations
                        # succeed; a failed stats read must not lose it.
                        hold.back_at = time.monotonic()
                        raise
                    print('The cellular default route is back', 'behind Wi-Fi' if others else 'as the only way out', flush=True)
                    last = None
                return
            if restore_at is not None:
                if time.monotonic() >= restore_at:
                    restore_answered(routed)
                return
            if not routed and not others:
                fresh_interval()
                run('ip', 'route', 'add', 'default', 'dev', dev, 'src', address, 'metric', '700')
                check_at = time.monotonic() + HEALTH_INTERVAL
                print('Nothing else leads out; the cellular default route is back', flush=True)
                retry_at = None
            elif not routed and retry_at is not None and time.monotonic() >= retry_at:
                # An explicit interface bind uses this existing rmnet even
                # without its default route. Never re-run find_device here:
                # another rmnet may carry IMS or a modem-owned attach bearer.
                retries += 1
                # Consume the attempt before probing; a subprocess error is
                # bounded too, rather than retried every watch iteration.
                retry_at = (time.monotonic() + RECHECK_DELAYS[retries]
                            if retries < len(RECHECK_DELAYS) else None)
                print('Rechecking the cellular bearer:', retries, 'of', len(RECHECK_DELAYS), flush=True)
                if answers(dev):
                    retry_at = None
                    # A failed ip operation can be retried without spending
                    # another probe, even when this was the last attempt.
                    restore_at = time.monotonic()
                    restore_answered(routed)
                elif retry_at is None:
                    print('Cellular bearer still answers no probe; rechecks exhausted, route remains removed', flush=True)
                else:
                    print('Cellular bearer still answers no probe; route remains removed', flush=True)
            elif time.monotonic() >= check_at:
                now = counters(json.loads(run('ip', '-j', '-s', 'link', 'show', 'dev', dev)))
                silent = looks_silent(routed, seen, now)
                # Even a probe subprocess failure gets a full interval,
                # not another attempt on the next half-second watch pass.
                seen = now
                check_at = time.monotonic() + HEALTH_INTERVAL
                if silent and not answers(dev):
                    run('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')
                    print('Cellular bearer carries nothing; its default route is removed', flush=True)
                    retries = 0
                    retry_at = time.monotonic() + RECHECK_DELAYS[0]
                    now = counters(json.loads(run('ip', '-j', '-s', 'link', 'show', 'dev', dev)))
                seen = now
                check_at = time.monotonic() + HEALTH_INTERVAL
        def announced(state):
            nonlocal retry_at, restore_at
            if not state:
                was_sleeping = hold.sleeping
                hold.over(time.monotonic(), not roaming_blocked())
                # A withdrawn route has no SleepHold return, but its next
                # probe must still wait for the post-resume grace.
                if was_sleeping and retry_at is not None:
                    retry_at = max(retry_at, time.monotonic() + HEALTH_INTERVAL)
                if was_sleeping and restore_at is not None:
                    restore_at = max(restore_at, time.monotonic() + HEALTH_INTERVAL)
                return
            routes = json.loads(run('ip', '-j', 'route', 'show', 'default'))
            routed = any(r.get('dev') == dev and r.get('metric') == 700 for r in routes)
            if hold.announced(routed):
                run('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')
                print('Sleep announced; the cellular default route is away until it is over', flush=True)
        sleeps = SleepWatch()
        failing = None
        while not stopping and cp.online() and RESPONSE.exists():
            error = guarded(watch)
            if error and not failing:
                print('Network check failed, retrying:', type(error).__name__, flush=True)
            elif failing and not error:
                print('Network checks work again', flush=True)
            failing = error
            for state in sleeps.wait(2 if error else .5):
                guarded(lambda state=state: announced(state))
    except InterruptedError:
        # Stopped while probing: find_device has put the candidate back.
        pass
    finally:
        if sleeps:
            sleeps.close()
        if resolver:
            resolver.restore()
        if dev:
            routes = json.loads(run('ip', '-j', 'route', 'show', 'default'))
            if any(r.get('dev') == dev and r.get('metric') == 700 for r in routes):
                run('ip', 'route', 'del', 'default', 'dev', dev, 'metric', '700')
            if addressed:
                run('ip', 'addr', 'del', address + '/32', 'dev', dev)
            run('ip', 'link', 'set', 'dev', dev, 'down')
            INTERFACE.unlink(missing_ok=True)
        os.close(lock)
        print('Cellular fallback configuration removed', flush=True)


if __name__ == '__main__':
    main()
