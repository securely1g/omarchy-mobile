#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Single-owner SIT IPC0 transport for the S5300 (CPIF /dev/umts_ipc0).

Every request goes through two guards: a fixed allow-list of the requests
this stack sends (each one used on this phone with its stock layout), and
the do-not-send list of device/cheetah/MODEM-SIT-RESEARCH.md section 5 (NV,
identity, carrier lock, AT forwarding, VSIM and satellite), so an edit to
the allow-list can't let one of those through. Dial and outgoing SMS are
refused unless the owner was opened for them. SIM_IO is refused too,
except the read-only ISIM EF_PCSCF and USIM EF_MSISDN reads, checked byte
by byte and enabled separately by the channel owner.
"""
from collections import deque
import fcntl
import math
import os
import select
import struct
import time

from isim import SIM_IO, check_request as check_sim_io
from msisdn import check_request as check_msisdn
from paths import IPC, RUN, open_channel, run_dir
from sit_names import NAMES

# Data/radio/IMS lifecycle, display state, read-only status, and incoming SMS
# ACK. SIM I/O is limited to the two guarded read-only files below; no PIN,
# subscription, APDU or vendor NV requests.
# GET_IMSI (0x0400, read-only, from 0.3.29) is sent once at start-up for the SIM's home
# network code, to choose the carrier settings; its answer is never logged or kept.
ALLOWED = {0x0000, 0x0102, 0x0108, 0x0200, 0x0400, 0x0600, 0x0601, 0x0602, 0x0603, 0x0613,
           0x061a, 0x061b, 0x0625, 0x0700, 0x0701, 0x0702, 0x0703, 0x0704, 0x070a,
           0x070b, 0x0710, 0x0711, 0x0800, 0x0801, 0x0748, 0x0749, 0x0750, 0x0902,
           0x091b, 0x0928, 0x0930, 0x0953, 0x0956, 0x0957, 0x0d07, 0x0d08, 0x0d1d,
           0x0d38, 0x0d39, 0x0d3a}
SMS = {0x0d1b}                              # AIMS_SEND_SMS
CALLS = {0x0d00, 0x0d02, 0x0d03, 0x0d0a}    # AIMS_DIAL, _ANSWER, _HANGUP, _SEND_DTMF

# The research note's do-not-send list, by name, plus the VSIM (0x0e) and
# satellite (0x13) families.
DENIED_NAMES = frozenset({
    'SET_RADIO_NODE_VALUE', 'SET_RADIO_NODE', 'EXEC_RADIO_NODE', 'SET_CFG_DEFAULT',
    'SET_ENG_MODE', 'SET_ENG_STRING_INPUT', 'SET_SELFLOG', 'SET_SELFLOG_PROFILE',
    'SET_MODEM_LOG_DUMP', 'SET_CARRIER_INFO_IMSI_ENCRYPTION', 'SET_CARRIER_RESTRICTIONS',
    'SET_CARRIER_RESTRICTIONS_V2', 'OEM_SET_CARRIER_CONFIG_MANIFEST', 'SET_SIM_CARD_POWER',
    'SET_FACILITY_LOCK', 'CHG_SIM_PIN', 'CHG_SIM_PIN2', 'VERIFY_NETWORK_LOCK',
    'SET_FORWARDING_AT_COMMAND', 'SET_SATELLITE_MODE_SERVICE', 'SET_SATELLITE_PLMN_LIST',
})
DENIED_FAMILIES = (0x0e, 0x13)
DENIED = frozenset(i for i, n in NAMES.items()
                   if n in DENIED_NAMES or (i >> 8) in DENIED_FAMILIES)


def name(ident):
    return NAMES.get(ident, f'0x{ident:04x}')


class ModemError(RuntimeError):
    def __init__(self, error, payload):
        super().__init__('modem rejected request with error ' + str(error))
        self.error = error
        self.payload = payload  # private; never include payload in str/repr


# OEM_SET_CARRIER_CONFIG_MANIFEST stays on the do-not-send list; the one
# exception is the reply to the modem's own request, sent by an owner opened
# with a manifest configured (carrier_manifest.py).
MANIFEST = 0x4600


def check(ident, *, sms=False, calls=False, manifest=False, isim_pcscf=False,
          msisdn=False, payload=b''):
    if manifest and ident == MANIFEST:
        return
    # SIM_IO (0x0208) stays outside the general allow-list. Separate owner
    # flags authorize GET RESPONSE / READ RECORD for either USIM EF_MSISDN
    # or ISIM EF_PCSCF; neither grants generic SIM access.
    if ident == SIM_IO:
        if msisdn and len(payload) > 1 and payload[1] == 2:
            check_msisdn(payload)
            return
        if not isim_pcscf:
            raise ValueError('request outside the allow-list')
        check_sim_io(payload)
        return
    if ident in DENIED or (ident >> 8) in DENIED_FAMILIES:
        raise ValueError('request on the do-not-send list')
    if not (ident in ALLOWED or (sms and ident in SMS) or (calls and ident in CALLS)):
        raise ValueError('request outside the allow-list')


class _Transaction:
    """An owner-bound wait handle; never a cancellation of a modem command."""
    def __init__(self, token, ident, deadline):
        self.token, self.ident, self.deadline = token, ident, deadline
        self.packet = None

    def __repr__(self):
        return '<SIT transaction>'


class Sit:
    def __init__(self, *, allow_sms=False, allow_calls=False, allow_manifest=False,
                 allow_isim_pcscf=False, allow_msisdn=False, device=None):
        self.allow_sms = allow_sms
        self.allow_calls = allow_calls
        self.allow_manifest = allow_manifest
        self.allow_isim_pcscf = allow_isim_pcscf
        self.allow_msisdn = allow_msisdn
        run_dir()
        self.lock = os.open(RUN / 'ipc0.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.fd = open_channel(device or IPC)
        except BaseException:
            os.close(self.lock)
            raise
        self.token = int.from_bytes(os.urandom(4), 'little') & 0x7fffffff
        self.buffer = bytearray()
        self.indications = deque()
        self.pending = {}
        self.closed = False

    def close(self):
        self.closed = True
        self.pending = {}
        os.close(self.fd)
        os.close(self.lock)

    def read_packet(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buffer) >= 6:
                kind, _, _, length = struct.unpack_from('<BBHH', self.buffer)
                if kind not in (1, 2) or not (8 if kind == 2 else 12) <= length <= 32768:
                    raise RuntimeError('invalid SIT framing')
                if len(self.buffer) >= length:
                    packet = bytes(self.buffer[:length])
                    del self.buffer[:length]
                    return packet
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([self.fd], [], [], remaining)
            if not ready:
                return None
            try:
                chunk = os.read(self.fd, 65536)
            except BlockingIOError:
                continue
            if not chunk:
                raise EOFError('SIT channel closed')
            self.buffer.extend(chunk)
            if len(self.buffer) > 65536:
                raise RuntimeError('SIT receive limit exceeded')

    def begin_request(self, ident, payload=b'', timeout=8, *, manifest_reply=False):
        """Send once without waiting. All reads still belong to this owner.

        A synchronous call/SMS request may run while this handle is pending;
        response routing uses its captured token, never the current token.
        """
        check(ident, sms=getattr(self, 'allow_sms', False),
              calls=getattr(self, 'allow_calls', False),
              manifest=manifest_reply and getattr(self, 'allow_manifest', False),
              isim_pcscf=getattr(self, 'allow_isim_pcscf', False),
              msisdn=getattr(self, 'allow_msisdn', False), payload=payload)
        if getattr(self, 'closed', False):
            raise RuntimeError('SIT owner is closed')
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError('SIT timeout must be positive')
        if not hasattr(self, 'pending'):
            self.pending = {}
        if len(self.pending) >= 4:
            raise RuntimeError('SIT pending request limit exceeded')
        for _ in range(len(self.pending) + 1):
            self.token = (self.token + 1) & 0xffffffff
            if self.token not in self.pending:
                break
        handle = _Transaction(self.token, ident, time.monotonic() + timeout)
        data = struct.pack('<BBHHIBB', 0, 0, ident, 12 + len(payload), handle.token, 0, 0) + payload
        # Register before writing; a partial write has an unknown outcome,
        # but must not leave an unreachable local wait or retransmit it.
        self.pending[handle.token] = handle
        try:
            if os.write(self.fd, data) != len(data):
                raise RuntimeError('short SIT write')
        except BaseException:
            self.pending.pop(handle.token, None)
            raise
        return handle

    def _pending_handle(self, handle):
        if getattr(self, 'closed', False):
            raise RuntimeError('SIT owner is closed')
        if not isinstance(handle, _Transaction) or getattr(self, 'pending', {}).get(handle.token) is not handle:
            raise ValueError('SIT transaction is not pending on this owner')

    def cancel_request(self, handle):
        """Abandon a local wait only; a transmitted mutation may still finish."""
        self._pending_handle(handle)
        del self.pending[handle.token]

    def poll_request(self, handle):
        """Return None while pending, bytes on success, or its own error.

        No device reads or writes: next_indication/drain_ready route packets,
        allowing the service to handle call and socket events between polls.
        """
        self._pending_handle(handle)
        if handle.packet is not None:
            del self.pending[handle.token]
            packet = handle.packet
            print(f'SIT {name(handle.ident)}: error={packet[10]} length={len(packet)}', flush=True)
            if packet[10]:
                raise ModemError(packet[10], packet[12:])
            return packet[12:]
        if time.monotonic() >= handle.deadline:
            del self.pending[handle.token]
            raise TimeoutError(f'SIT {name(handle.ident)}')
        return None

    def _route_packet(self, packet):
        kind, _, message, _ = struct.unpack_from('<BBHH', packet)
        if kind == 2:
            # Telemetry is a snapshot. Preserve durable call/SMS FIFO while
            # retaining only the latest physical-channel/signal report.
            if message in (0x0742, 0x0906):
                for old in self.indications:
                    if struct.unpack_from('<H', old, 2)[0] == message:
                        self.indications.remove(old)
                        break
            if len(self.indications) >= 256:
                raise RuntimeError('unprocessed indication limit exceeded')
            self.indications.append(packet)
        else:
            handle = getattr(self, 'pending', {}).get(struct.unpack_from('<I', packet, 6)[0])
            if handle is not None and handle.ident == message and handle.packet is None \
                    and time.monotonic() < handle.deadline:
                handle.packet = packet

    def request(self, ident, payload=b'', timeout=8, *, manifest_reply=False):
        handle = self.begin_request(ident, payload, timeout, manifest_reply=manifest_reply)
        try:
            while True:
                result = self.poll_request(handle)
                if result is not None:
                    return result
                packet = self.read_packet(max(0, handle.deadline - time.monotonic()))
                if packet is None:
                    raise TimeoutError(f'SIT {name(ident)}')
                self._route_packet(packet)
        finally:
            if getattr(self, 'pending', {}).get(handle.token) is handle:
                del self.pending[handle.token]

    def drain_ready(self, limit=32):
        """Bounded positive reads, queueing events only; True means drained.

        Callers must pump queued events and recheck their guards afterward.
        A future indication can still arrive after this finite observation.
        """
        if not 1 <= limit <= 256:
            raise ValueError('SIT drain limit out of range')
        for _ in range(limit):
            packet = self.read_packet(.001)
            if packet is None:
                return not self.buffer
            self._route_packet(packet)
        return False

    def next_indication(self, timeout=1):
        if self.indications:
            return self.indications.popleft()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            packet = self.read_packet(deadline - time.monotonic())
            if packet is None:
                return None
            self._route_packet(packet)
            if self.indications:
                return self.indications.popleft()
        return None
