# SPDX-License-Identifier: MIT
"""Private RAM-only protocol between sitd and its single network helper.

The daemon owns STATE; the helper owns ACK and LEASE. Ownership is separate
from this availability protocol. Nothing here opens a modem channel.
"""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
import uuid

import paths

STATE = paths.RUN / 'network-lifecycle.json'
ACK = paths.RUN / 'network-lifecycle-ack.json'
LEASE = paths.RUN / 'network-lifecycle-lease.json'
OWNED = paths.RUN / 'network-lifecycle-owned.json'
SIZES = (132, 234, 239, 246, 280, 292)
LIMIT = 4096
REASONS = frozenset(('invalid-state', 'stale-generation', 'epoch-changed',
    'cid-changed', 'binding-mismatch', 'interface-changed', 'host-conflict',
    'host-operation', 'proof-failed', 'sleeping', 'roaming', 'unavailable',
    'setup-failed', 'setup-unknown', 'initialization-failed', 'not-quiesced',
    'protocol-error', 'helper-stopped', 'peer-timeout', 'owner-stopped',
    'confirmed-absent', 'canceled'))


class ProtocolError(ValueError):
    """A fixed error label; never include private input in exceptions."""


def new_epoch():
    return uuid.uuid4().hex


def clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _binding(value):
    return value is None or (type(value) is dict and set(value) == {'dev', 'ifindex'}
        and isinstance(value['dev'], str)
        and re.fullmatch(r'rmnet(?:[0-9]|[12][0-9])', value['dev']) is not None
        and _integer(value['ifindex'], 1, 0x7fffffff))


def _timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _reason(value):
    return value is None or isinstance(value, str) and value in REASONS


def _common(value):
    return (type(value) is dict and value.get('version') == 1
        and type(value.get('version')) is int
        and isinstance(value.get('epoch'), str)
        and re.fullmatch(r'[0-9a-f]{32}', value['epoch']) is not None
        and _integer(value.get('generation'), 0, 0x7fffffff)
        and _integer(value.get('cid'), 1, 15) and value['cid'] != 2
        and _binding(value.get('binding')))


def _addresses(data):
    address = ipaddress.IPv4Address(data[5:9])
    servers = list(dict.fromkeys(ipaddress.IPv4Address(data[i:i + 4])
                               for i in (0x1a, 0x2e) if any(data[i:i + 4])))
    if not servers or any(a.is_unspecified or a.is_multicast or a.is_loopback
                          or int(a) == 0xffffffff for a in [address] + servers):
        raise ProtocolError('invalid-state')
    return str(address), [str(a) for a in servers]


def fallback_resolver_text(servers):
    return '# Omamobile cellular fallback (session only)\n' + ''.join(
        'nameserver ' + server + '\n' for server in servers)


def _validate(value, kind):
    fields = {'version', 'epoch', 'generation', 'cid', 'binding'}
    fields |= ({'response_hex', 'address_state', 'route_state', 'dns'} if kind == 'host'
               else {'phase', 'response_hex', 'reason'} if kind == 'state'
               else {'phase', 'reason', 'updated'} if kind == 'ack'
               else {'desired', 'awake', 'updated'})
    if not _common(value) or set(value) != fields:
        raise ProtocolError('invalid-state')
    if kind == 'host':
        if value['binding'] is None or value['address_state'] not in ('none', 'adding', 'owned', 'removing') \
                or value['route_state'] not in ('none', 'adding', 'owned', 'removing'):
            raise ProtocolError('invalid-state')
        active = {key: value[key] for key in ('version', 'epoch', 'generation', 'cid', 'binding', 'response_hex')}
        active.update(phase='active', reason=None)
        _validate(active, 'state')
        dns = value['dns']
        if type(dns) is not dict or dns.get('kind') not in ('none', 'file', 'resolved'):
            raise ProtocolError('invalid-state')
        if dns['kind'] == 'none':
            valid = set(dns) == {'kind'}
        elif dns['kind'] == 'resolved':
            valid = set(dns) == {'kind', 'state'} and dns['state'] in ('setting', 'owned', 'releasing')
        else:
            _, servers = _addresses(bytes.fromhex(value['response_hex']))
            expected = fallback_resolver_text(servers)
            # A previous build may have left a journal and resolver file in this boot.
            legacy = expected.replace('# Omamobile ', '# Omarchy Mobile ', 1)
            valid = (set(dns) == {'kind', 'state', 'path', 'original', 'owned'}
                     and dns['state'] in ('setting', 'owned', 'releasing')
                     and isinstance(dns['path'], str) and dns['path'].startswith('/')
                     and '\0' not in dns['path'] and len(dns['path']) <= 512
                     and isinstance(dns['original'], str) and len(dns['original']) <= 2048
                     and dns['owned'] in (expected, legacy))
    elif kind == 'lease':
        valid = (type(value['desired']) is bool and type(value['awake']) is bool
                 and _timestamp(value['updated']))
    elif kind == 'ack':
        valid = (value['phase'] in ('quiesced', 'applied', 'unavailable', 'failed')
                 and _reason(value['reason']) and _timestamp(value['updated'])
                 and (value['phase'] not in ('quiesced', 'applied') or value['binding'] is not None))
    else:
        valid = (value['phase'] in ('active', 'quiesce', 'unavailable')
                 and _reason(value['reason'])
                 and (value['generation'] == 0 or value['binding'] is not None
                      or value['phase'] == 'unavailable'))
        if value['phase'] == 'active':
            encoded = value['response_hex']
            if not isinstance(encoded, str) or len(encoded) not in {n * 2 for n in SIZES} \
                    or re.fullmatch('[0-9a-f]+', encoded) is None:
                raise ProtocolError('invalid-state')
            data = bytes.fromhex(encoded)
            status, cid, active, pdp = struct.unpack_from('<HBBB', data)
            valid = valid and status == 0 and cid == value['cid'] and active in (1, 2) and pdp in (1, 3)
            _addresses(data)
        else:
            valid = valid and value['response_hex'] is None
    if not valid:
        raise ProtocolError('invalid-state')
    return value


def _read(path, kind):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError:
        raise ProtocolError('invalid-state') from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() \
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > LIMIT:
            raise ProtocolError('invalid-state')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ProtocolError('invalid-state')
        value = json.loads(raw)
        return _validate(value, kind)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise ProtocolError('invalid-state') from None
    finally:
        os.close(fd)


def _write(path, value, kind):
    _validate(value, kind)
    encoded = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > LIMIT:
        raise ProtocolError('invalid-state')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(encoded)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return value


def read_state():
    return _read(STATE, 'state')


def publish_state(epoch, generation, phase, cid, *, binding=None, response=None, reason=None):
    if response is not None and not isinstance(response, (bytes, bytearray)):
        raise ProtocolError('invalid-state')
    value = dict(version=1, epoch=epoch, generation=generation, phase=phase,
                 cid=cid, binding=binding, response_hex=response.hex() if response is not None else None,
                 reason=reason)
    _validate(value, 'state')
    old = read_state()
    if old is not None:
        if old == value:
            return value
        if epoch != old['epoch'] or cid != old['cid'] \
                or generation != old['generation'] + 1 \
                or old['binding'] is not None and binding != old['binding']:
            raise ProtocolError('stale-generation')
    elif generation != 0:
        raise ProtocolError('stale-generation')
    return _write(STATE, value, 'state')


def publish_ack(state, phase, *, binding=None, reason=None):
    _validate(state, 'state')
    value = {key: state[key] for key in ('version', 'epoch', 'generation', 'cid')}
    value.update(phase=phase, binding=binding, reason=reason, updated=clock())
    return _write(ACK, value, 'ack')


def read_ack(epoch=None, generation=None):
    value = _read(ACK, 'ack')
    if value is None or epoch is not None and value['epoch'] != epoch \
            or generation is not None and value['generation'] != generation:
        return None
    return value


def publish_lease(state, *, desired, awake, binding=None, now=None):
    _validate(state, 'state')
    value = {key: state[key] for key in ('version', 'epoch', 'generation', 'cid')}
    value.update(desired=desired, awake=awake, binding=binding,
                 updated=clock() if now is None else now)
    return _write(LEASE, value, 'lease')


def read_lease(epoch=None, *, max_age=5.0, now=None):
    value = _read(LEASE, 'lease')
    if value is None or epoch is not None and value['epoch'] != epoch:
        return None
    now = clock() if now is None else now
    if max_age is not None and (not _timestamp(now) or not _timestamp(max_age)
                               or not 0 <= now - value['updated'] <= max_age):
        return None
    return value


def response_bytes(state):
    _validate(state, 'state')
    return bytes.fromhex(state['response_hex']) if state['phase'] == 'active' else None


def configuration(state):
    data = response_bytes(state)
    if data is None:
        raise ProtocolError('invalid-state')
    return _addresses(data)


def read_host():
    """Helper-only cleanup evidence; never a source of recovery authority."""
    return _read(OWNED, 'host')


def publish_host(value):
    return _write(OWNED, value, 'host')
