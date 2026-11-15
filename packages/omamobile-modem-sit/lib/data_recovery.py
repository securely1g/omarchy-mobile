# SPDX-License-Identifier: MIT
"""Opt-in, once-per-boot repair of a proven absent, still-reserved PDN.

All modem work advances on the existing owner's asynchronous requests. An
indication is only a hint; host quiescence, fresh absence proofs and an
independent sleep guard precede the sole possible SETUP. No address, APN,
raw reply or foreign CID is returned or logged here.
"""
import json
import os
from pathlib import Path
import struct
import subprocess

import data_call
import paths

SPENT = paths.RUN / 'data-recovery-spent.json'
GUARD_UNIT = 'omamobile-data-recovery-guard.service'
ITEM_SIZES = (132, 234, 239, 246, 280, 292)
PEER_TIMEOUT = 30.0
CANDIDATE_TIMEOUT = 90.0


class Unsafe(RuntimeError):
    pass


class SleepGuard:
    """A logind block inhibitor in a unit outside sitd's control group."""
    def __init__(self, *, unit=GUARD_UNIT, who='omamobile-data-recovery', permanent=False):
        self.unit, self.who, self.permanent = unit, who, bool(permanent)
        self.created = False
        self.verify = None
        self.pid = None
        self.start = None
        command = ['/usr/bin/systemd-run', '--quiet', '--collect', '--unit=' + self.unit,
                   '--property=Restart=on-failure']
        if self.permanent:
            command.append('--property=RefuseManualStop=yes')
        self.process = subprocess.Popen(command + [
            '/usr/bin/systemd-inhibit', '--what=sleep',
            '--mode=block', '--who=' + self.who,
            '--why=Internet bearer recovery outcome must be resolved before sleep',
            '/usr/bin/sleep', 'infinity'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _identity(self, pid):
        root = Path('/proc') / str(pid)
        group = (root / 'cgroup').read_text()
        if not any(line.split(':', 2)[-1] == '/system.slice/' + self.unit
                   for line in group.splitlines()):
            raise Unsafe('unavailable')
        fields = (root / 'stat').read_text().rsplit(')', 1)
        if len(fields) != 2 or len(fields[1].split()) < 20:
            raise Unsafe('unavailable')
        return fields[1].split()[19]

    def ready(self):
        if self.pid is not None:
            return self.held()
        result = self.process.poll()
        if result is None:
            return False
        if result != 0:
            raise Unsafe('unavailable')
        self.created = True
        if self.verify is None:
            self.verify = subprocess.Popen(['/usr/bin/systemd-inhibit', '--list', '--json=short',
                                            '--no-pager'], stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL)
            return False
        if self.verify.poll() is None:
            return False
        if self.verify.returncode:
            raise Unsafe('unavailable')
        raw = self.verify.stdout.read(65537)
        if len(raw) > 65536:
            raise Unsafe('unavailable')
        rows = json.loads(raw)
        if not isinstance(rows, list):
            raise Unsafe('unavailable')
        for row in rows:
            if not isinstance(row, dict):
                continue
            row = {key.lower(): value for key, value in row.items()}
            pid = row.get('pid')
            if row.get('who') == self.who and row.get('mode') == 'block' \
                    and 'sleep' in str(row.get('what', '')).split(':') \
                    and type(row.get('uid')) is int and row['uid'] == 0 \
                    and type(pid) is int and pid > 0:
                self.start = self._identity(pid)
                self.pid = pid
                self.verify.stdout.close()
                self.verify = None
                return self.held()
        # The unit can be running before logind has accepted its inhibitor.
        self.verify.stdout.close()
        self.verify = None
        return False

    def held(self):
        if self.pid is None:
            return False
        try:
            return self._identity(self.pid) == self.start
        except (OSError, ValueError, Unsafe):
            return False

    def close(self):
        if self.verify and self.verify.poll() is None:
            self.verify.terminate()
        if self.created and not self.permanent:
            subprocess.Popen(['/usr/bin/systemctl', '--no-block', 'stop', self.unit],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.created = False


def _settings(settings):
    return tuple((section, tuple(sorted(settings[section].items()))) for section in sorted(settings))


def _entries(payload):
    if not isinstance(payload, (bytes, bytearray)):
        raise Unsafe('protocol-error')
    items = data_call.entries(payload)
    if any(item[3] not in (0, 1, 2) or item[4] not in (1, 2, 3) for item in items):
        raise Unsafe('protocol-error')
    return {item[2]: item for item in items}


def _identity(item):
    # SETUP and GET can use different supported record widths. Compare the
    # stock-derived fields data_call already understands, not padding,
    # representation width or unparsed extension bytes. Active 1 and 2
    # both mean the PDN exists; link dormancy is not a new identity.
    if len(item) not in ITEM_SIZES:
        raise Unsafe('protocol-error')
    def addresses(slots, size):
        return tuple(sorted({bytes(item[i:i + size]) for i in slots if any(item[i:i + size])}))
    pcscf4, pcscf6 = data_call.pcscf_addresses(item)
    return (struct.unpack_from('<H', item)[0], item[2],
            1 if item[3] in (1, 2) else item[3], item[4],
            bytes(item[5:9]), bytes(item[9:25]),
            addresses((0x1a, 0x2e), 4), addresses((0x1e, 0x32), 16),
            tuple(sorted(pcscf4)), tuple(sorted(pcscf6)))


class Recovery:
    def __init__(self, service, *, enabled=False, lifecycle=None, inhibitor_factory=None,
                 clock=None, settings_reader=None):
        self.service, self.client, self.enabled = service, service.client, bool(enabled)
        self.state = 'disabled' if not self.enabled else 'new'
        self.reason = None
        self.available = False
        self.epoch = None
        self.generation = 0
        self.binding = None
        self.original = None
        self.handle = None
        self.guard = None
        self.spent = False
        self.uncertain = False
        self._invalid = None
        self._dirty = False
        self._indication_generation = 0
        self._latest = None
        self._request_generation = 0
        self._deadline = None
        self._due = 0
        self._baseline = None
        self._ps = None
        self._candidate_ps = None
        self._first_generation = None
        self._new_response = None
        self._inventory = None
        self._published = False
        self._manifest = None
        self._phase_since = 0
        self._peer_missing_since = None
        self._settings_reader = settings_reader or paths.config
        self._config = _settings(service.settings)
        self._guard_factory = inhibitor_factory or SleepGuard
        if self.enabled:
            if lifecycle is None:
                import network_lifecycle as lifecycle
            self.lifecycle = lifecycle
            self.clock = clock or lifecycle.clock
        else:
            self.lifecycle = None
            self.clock = clock

    @property
    def guard_held(self):
        return bool(self.guard and self.guard.held())

    def observe(self, payload):
        if self.enabled:
            self.available = False
            self._indication_generation += 1
            self._dirty = True
            self._latest = bytes(payload[:4382]) if isinstance(payload, (bytes, bytearray)) else None

    def invalidate(self, reason='canceled'):
        if self.enabled:
            self._invalid = 'canceled'

    def arm(self):
        if self.enabled and self.state == 'new':
            self.state = 'arm-radio'
            self._deadline = self.clock() + CANDIDATE_TIMEOUT

    def _cancel(self):
        if self.handle is not None:
            try:
                self.client.cancel_request(self.handle)
            except (OSError, RuntimeError, ValueError):
                pass
            self.handle = None

    def _fail(self, reason):
        self._cancel()
        self.available = False
        if self.state == 'unavailable':
            return
        self.state, self.reason = 'unavailable', reason
        if self.epoch is not None and self.original is not None:
            try:
                if self._manifest is None or self.lifecycle.read_state() == self._manifest:
                    if self._manifest is not None:
                        self.generation = self._manifest['generation'] + 1
                    self._publish('unavailable', reason=reason)
            except (OSError, ValueError):
                pass
        if self.guard and not self.uncertain:
            self.guard.close()
            self.guard = None

    def close(self):
        if self.enabled:
            self._fail('owner-stopped')

    def _files(self):
        expected = {}
        for name in (data_call.STATE, data_call.paths(data_call.IMS_CID)[0], data_call.MODEM_OWNED):
            expected[name] = name.read_bytes() if name.exists() else None
        return expected

    def _context(self, *, check_calls=True):
        if self._invalid or getattr(self.service, 'release_unconfirmed', False) \
                or check_calls and (self.service.live() or getattr(self.service, 'audio', None) is not None):
            raise Unsafe('canceled')
        if getattr(self.service, 'radio', None) != 'on':
            raise Unsafe('canceled')
        if _settings(self._settings_reader()) != self._config:
            raise Unsafe('canceled')
        if self.original is not data_call.original_setup(self.client):
            raise Unsafe('canceled')
        if self._inventory is not None and self._files() != self._inventory:
            raise Unsafe('canceled')
        if self._manifest is not None and self.lifecycle.read_state() != self._manifest:
            raise Unsafe('epoch-changed')
        if not self._published:
            data_call.recovery_payload(self.client, self.original)

    def _peer(self, *, generation=None, ack=None):
        generation = self.generation if generation is None else generation
        ack = ack or ('quiesced' if generation == 1 else 'applied')
        value = self.lifecycle.read_ack(self.epoch, generation)
        # Terminal helper failures take precedence over its awake flag or
        # final stopped lease. Normal sleep alone is not a helper failure.
        if value is not None:
            if value['cid'] != self.original.cid:
                raise Unsafe('cid-changed')
            if value['phase'] in ('failed', 'unavailable'):
                raise Unsafe(value['reason'] or 'unavailable')
        lease = self.lifecycle.read_lease(self.epoch, now=self.clock())
        if lease is None:
            return self._missing_peer()
        if not lease['desired']:
            raise Unsafe('helper-stopped')
        if lease['cid'] != self.original.cid:
            raise Unsafe('cid-changed')
        if lease['generation'] > generation:
            raise Unsafe('stale-generation')
        if lease['generation'] != generation:
            return self._missing_peer()
        if self.binding is not None and lease['binding'] != self.binding:
            raise Unsafe('binding-mismatch')
        if value is None:
            return self._missing_peer()
        if not self._phase_since <= value['updated'] <= self.clock():
            raise Unsafe('protocol-error')
        if value['phase'] != ack:
            return self._missing_peer()
        if not value['binding'] or value['binding'] != lease['binding']:
            raise Unsafe('binding-mismatch')
        if self.binding is not None and value['binding'] != self.binding:
            raise Unsafe('binding-mismatch')
        self.binding = dict(value['binding'])
        self._peer_missing_since = None
        return lease['awake']

    def _missing_peer(self):
        now = self.clock()
        if self._peer_missing_since is None:
            self._peer_missing_since = now
        elif now - self._peer_missing_since > PEER_TIMEOUT:
            raise Unsafe('peer-timeout')
        return False

    def _request(self, ident, payload=b'', timeout=5):
        if self.handle is None:
            self._request_generation = self._indication_generation
            self.handle = self.client.begin_request(ident, payload, timeout=timeout)
            return None
        result = self.client.poll_request(self.handle)
        if result is not None:
            self.handle = None
        return result

    def _registration(self, payload):
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 4:
            raise Unsafe('protocol-error')
        state = (payload[0], payload[1], payload[3])
        if state[0] == 5 and not self.service.settings['data'].getboolean('roaming', True):
            raise Unsafe('roaming')
        return state

    @staticmethod
    def _radio_on(payload):
        # GET_RADIO_POWER is a u32 Android radio-state enum. 1 is OFF;
        # this stack recognizes 2 and the observed cheetah value 10 as ON.
        return isinstance(payload, (bytes, bytearray)) and len(payload) == 4 \
            and struct.unpack('<I', payload)[0] in (2, 10)

    def _compatible_registration(self, state):
        # LTE and LTE-CA may replace one another without changing the
        # captured SETUP access byte. Never rewrite that original payload.
        if self.original.payload[1] not in (14, 20) or state[2] not in (14, 20):
            raise Unsafe('canceled')
        return state[0] in (1, 5) and state[1] == 0 and state[0] == self._ps[0]

    def _foreign(self, items):
        return {cid: _identity(item) for cid, item in items.items() if cid != self.original.cid}

    def _allowed(self):
        owned = set()
        for name, expected in ((data_call.STATE, self.original.cid),
                               (data_call.paths(data_call.IMS_CID)[0], data_call.IMS_CID)):
            if not name.exists():
                continue
            value = json.loads(name.read_bytes())
            if not isinstance(value, dict) or type(value.get('cid')) is not int \
                    or value['cid'] != expected or type(value.get('session')) is not int \
                    or not 0 <= value['session'] <= 15:
                raise Unsafe('invalid-state')
            owned.add(expected)
        modem = set()
        if data_call.MODEM_OWNED.exists():
            value = json.loads(data_call.MODEM_OWNED.read_bytes())
            values = value.get('modem-owned') if isinstance(value, dict) else None
            if not isinstance(values, list) or any(type(cid) is not int or not 1 <= cid <= 15
                                                   for cid in values):
                raise Unsafe('invalid-state')
            modem = set(values)
        if owned & modem:
            raise Unsafe('invalid-state')
        return owned, modem

    def _check_list(self, payload, *, target=None):
        items = _entries(payload)
        if self._foreign(items) != self._baseline:
            raise Unsafe('cid-changed')
        found = items.get(self.original.cid)
        if target is not None:
            if found is None or _identity(found) != _identity(target):
                raise Unsafe('setup-unknown')
        return found

    def _publish(self, phase, *, response=None, reason=None):
        self._phase_since = self.clock()
        self._manifest = self.lifecycle.publish_state(self.epoch, self.generation, phase,
            self.original.cid, binding=self.binding, response=response, reason=reason)

    def _spend(self):
        # A partial marker or any previous marker is a spent budget too.
        self.spent, self.uncertain = True, True
        fd = os.open(SPENT, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC |
                     os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(dict(version=1, epoch=self.epoch, cid=self.original.cid), out)
            out.flush()
            os.fsync(out.fileno())

    def tick(self, *, quiet=False):
        if not self.enabled or self.state in ('disabled', 'new', 'unavailable'):
            return
        try:
            # Cancellation and deadlines never depend on an idle transport.
            # Continuous reports must not strand a quiesced host or a write.
            if self._invalid:
                raise Unsafe('canceled')
            if self._deadline is not None and self.clock() > self._deadline:
                raise Unsafe('peer-timeout')
            if self.original is not None:
                idle = self.state in ('arm-radio', 'arm-ps', 'arm-list', 'wait-initial', 'active')
                self._context(check_calls=not idle)
            if self.state == 'active':
                self.available = self._peer(ack='applied') and not self._dirty
            if self.state in ('wait-quiesce', 'second-radio', 'second-ps', 'check-second',
                              'send', 'setup', 'final-list', 'wait-applied') and not self.guard_held:
                raise Unsafe('setup-unknown' if self.uncertain else 'unavailable')
            if self.state in ('second-radio', 'second-ps', 'check-second', 'send', 'setup', 'final-list') \
                    and not self._peer(ack='quiesced'):
                raise Unsafe('setup-unknown' if self.uncertain else 'not-quiesced')
            if not quiet:
                return
            self._tick()
        except (OSError, EOFError, RuntimeError, ValueError, TypeError, KeyError) as error:
            reason = str(error) if isinstance(error, Unsafe) else ('setup-unknown' if self.spent else 'protocol-error')
            self._fail(reason)

    def _tick(self):
        now = self.clock()
        if self.state == 'arm-radio' and self.original is None:
            self.original = data_call.original_setup(self.client)
            if self.original is None:
                raise Unsafe('initialization-failed')
            data_call.recovery_payload(self.client, self.original)
            if SPENT.exists():
                self.spent, self.uncertain = True, True
                raise Unsafe('setup-unknown')
            if self.lifecycle.read_state() is not None or self.lifecycle.read_ack() is not None \
                    or self.lifecycle.read_lease(max_age=None) is not None:
                raise Unsafe('epoch-changed')
            self._inventory = self._files()
            self.epoch = self.lifecycle.new_epoch()
            self._deadline = now + CANDIDATE_TIMEOUT
        if self.state in ('arm-radio', 'arm-ps', 'arm-list', 'wait-initial', 'active') \
                and (self.service.live() or getattr(self.service, 'audio', None) is not None):
            if self.state == 'active':
                self.available = self._peer(ack='applied') and not self._dirty
            return
        self._context()
        if self.state not in ('active', 'wait-initial') and self._deadline is not None and now > self._deadline:
            raise Unsafe('peer-timeout')
        if self.state == 'arm-radio':
            value = self._request(0x0801)
            if value is not None:
                if not self._radio_on(value):
                    raise Unsafe('canceled')
                self.state = 'arm-ps'
        elif self.state == 'arm-ps':
            value = self._request(0x0701)
            if value is not None:
                self._ps = self._registration(value)
                if not self._compatible_registration(self._ps):
                    raise Unsafe('initialization-failed')
                self.state = 'arm-list'
        elif self.state == 'arm-list':
            value = self._request(0x0602)
            if value is not None:
                if self._request_generation != self._indication_generation:
                    return
                items = _entries(value)
                owned, modem = self._allowed()
                if set(items) - (owned | modem) or not owned <= set(items) \
                        or self.original.cid not in items \
                        or any(item[3] not in (1, 2) or item[:2] != b'\0\0' for item in items.values()) \
                        or _identity(items[self.original.cid]) != _identity(self.original.response):
                    raise Unsafe('initialization-failed')
                self._baseline = self._foreign(items)
                self._dirty = False
                self._publish('active', response=self.original.response)
                self._deadline = now + PEER_TIMEOUT
                self.state = 'wait-initial'
        elif self.state == 'wait-initial':
            if self._peer(ack='applied'):
                self.available, self.state = True, 'active'
                self._deadline = None
            elif now > self._deadline:
                raise Unsafe('peer-timeout')
        elif self.state == 'active':
            self.available = self._peer(ack='applied')
            if self._dirty and self._peer():
                self.available = False
                self._deadline = now + CANDIDATE_TIMEOUT
                self.state = 'check-ps'
        elif self.state == 'check-ps':
            if not self._peer() or now < self._due:
                return
            value = self._request(0x0701)
            if value is not None:
                state = self._registration(value)
                if not self._compatible_registration(state):
                    self._due = now + 2
                    return
                self._candidate_ps = state
                self.state = 'check-first'
        elif self.state == 'check-first':
            if not self._peer():
                raise Unsafe('sleeping')
            value = self._request(0x0602)
            if value is not None:
                if self._request_generation != self._indication_generation:
                    return
                found = self._check_list(value)
                if found is not None:
                    expected = self._new_response if self._published else self.original.response
                    if _identity(found) != _identity(expected):
                        raise Unsafe('cid-changed')
                    self._dirty = False
                    self.state, self.available = 'active', True
                    return
                if self.spent:
                    raise Unsafe('unavailable')
                self._first_generation = self._indication_generation
                self.guard = self._guard_factory()
                self._deadline = now + 10
                self.state = 'guard'
        elif self.state == 'guard':
            if not self._peer():
                raise Unsafe('sleeping')
            if self.guard.ready():
                self.generation = 1
                self._publish('quiesce', reason='confirmed-absent')
                self._deadline = now + PEER_TIMEOUT
                self.state = 'wait-quiesce'
        elif self.state == 'wait-quiesce':
            if not self.guard_held:
                raise Unsafe('unavailable')
            if self._peer(ack='quiesced'):
                self.state = 'second-radio'
        elif self.state == 'second-radio':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('not-quiesced')
            value = self._request(0x0801)
            if value is not None:
                if not self._radio_on(value):
                    raise Unsafe('canceled')
                self.state = 'second-ps'
        elif self.state == 'second-ps':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('not-quiesced')
            if now < self._due:
                return
            value = self._request(0x0701)
            if value is not None:
                state = self._registration(value)
                if not self._compatible_registration(state):
                    raise Unsafe('canceled')
                if state != self._candidate_ps:
                    self._candidate_ps = state
                    self._due = now + 2
                    return
                self.state = 'check-second'
        elif self.state == 'check-second':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('not-quiesced')
            value = self._request(0x0602)
            if value is not None:
                if self._check_list(value) is not None:
                    raise Unsafe('cid-changed')
                if self._indication_generation != self._first_generation:
                    raise Unsafe('stale-generation')
                self.state = 'send'
        elif self.state == 'send':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('not-quiesced')
            if self._indication_generation != self._first_generation:
                raise Unsafe('stale-generation')
            self._spend()
            self.handle = data_call.begin_recovery_setup(self.client, self.original)
            self.state = 'setup'
            self._deadline = now + 50
        elif self.state == 'setup':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('setup-unknown')
            value = self.client.poll_request(self.handle)
            if value is not None:
                self.handle = None
                # Reuse the lifecycle's exact successful IPv4 response guard.
                if len(value) not in ITEM_SIZES or value[2] != self.original.cid:
                    raise Unsafe('setup-unknown')
                self.lifecycle.configuration(dict(version=1, epoch=self.epoch, generation=2,
                    cid=self.original.cid, phase='active', binding=self.binding,
                    response_hex=bytes(value).hex(), reason=None))
                self._new_response = bytes(value)
                self._due = now
                self.state = 'final-list'
        elif self.state == 'final-list':
            if not self.guard_held or not self._peer(ack='quiesced'):
                raise Unsafe('setup-unknown')
            value = self._request(0x0602)
            if value is not None:
                if self._request_generation != self._indication_generation:
                    # Expected restoration indications are allowed, but need
                    # a newer fresh GET after their normal event processing.
                    return
                self._check_list(value, target=self._new_response)
                data_call.publish_recovery_response(self.client, self.original, self._new_response)
                self._published = True
                self.generation = 2
                self._publish('active', response=self._new_response)
                self.state = 'wait-applied'
                self._deadline = now + PEER_TIMEOUT
        elif self.state == 'wait-applied':
            if not self.guard_held:
                raise Unsafe('setup-unknown')
            if self._peer(ack='applied'):
                self.available, self.uncertain = True, False
                self._dirty = False
                self.state = 'active'
                self._deadline = None
                self.original = data_call.original_setup(self.client)
                self.guard.close()
                self.guard = None
