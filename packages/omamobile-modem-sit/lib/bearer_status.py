# SPDX-License-Identifier: MIT
"""Private, read-only comparison of the owned internet bearer with the modem.

Only the daemon's existing client sends one GET_DATA_CALL_LIST. Nothing is
claimed, released, cached or logged; addresses stay local to comparisons.
``available`` means the diagnostic has a valid ownership/setup baseline,
not that the bearer is active or that an internet packet was delivered.
"""
import json
import struct

import data_call
from sit import ModemError

GET_DATA_CALL_LIST = 0x0602
ITEM_SIZES = (132, 234, 239, 246, 280, 292)


def _ownership():
    try:
        owned = json.loads(data_call.STATE.read_text())
    except (OSError, ValueError):
        return None, None, 'ownership-unavailable'
    if not isinstance(owned, dict):
        return None, None, 'invalid-ownership'
    cid, session = owned.get('cid'), owned.get('session')
    if type(cid) is not int or not 1 <= cid <= 15 or cid == 2 \
            or type(session) is not int or not 0 <= session <= 15:
        return None, None, 'invalid-ownership'
    try:
        with data_call.RESPONSE.open('rb') as stream:
            setup = stream.read(max(ITEM_SIZES) + 1)
    except OSError:
        return cid, None, 'setup-unavailable'
    if len(setup) not in ITEM_SIZES or setup[2] != cid \
            or struct.unpack_from('<H', setup)[0] or setup[3] not in (1, 2) \
            or setup[4] not in (1, 2, 3):
        return cid, None, 'invalid-setup'
    return cid, setup, None


def read_status(client):
    """Return only fixed labels, owned-CID integers and presence/match flags.

    Unknown ownership still permits the read, but cannot claim a returned
    CID. An absent or invalid setup response makes comparisons unknown.
    """
    cid, setup, reason = _ownership()
    result = dict(status='unavailable', source='unavailable')
    if cid is not None:
        result['owned_cid'] = cid
    try:
        payload = client.request(GET_DATA_CALL_LIST, timeout=5)
    except TimeoutError:
        return dict(result, reason='timeout')
    except ModemError:
        return dict(result, reason='modem-error')
    except (OSError, EOFError, RuntimeError, ValueError):
        return dict(result, reason='query-unavailable')
    try:
        if not isinstance(payload, (bytes, bytearray)):
            raise ValueError('unexpected payload type')
        items = data_call.entries(payload)
        if any(item[3] not in (0, 1, 2) or item[4] not in (1, 2, 3) for item in items):
            raise ValueError('unsupported bearer state')
    except (RuntimeError, ValueError, TypeError):
        return dict(result, reason='unsupported-layout')
    result.update(status='unknown', source='modem')
    if cid is None:
        return dict(result, reason=reason)
    item = next((item for item in items if item[2] == cid), None)
    result['present'] = item is not None
    if item is not None:
        result.update(bearer_status=struct.unpack_from('<H', item)[0],
                      active=item[3], pdp_type=item[4],
                      ipv4_present=any(item[5:9]), ipv6_present=any(item[9:25]))
    if setup is None:
        return dict(result, reason=reason)
    result['status'] = 'available'
    if item is None:
        return dict(result, reason='owned-bearer-missing')
    for family, start, stop in (('ipv4', 5, 9), ('ipv6', 9, 25)):
        present = any(setup[start:stop])
        result[f'setup_{family}_present'] = present
        result[f'{family}_matches_setup'] = bool(
            present and result[f'{family}_present'] and item[start:stop] == setup[start:stop])
    result['pdp_matches_setup'] = item[4] == setup[4]
    if result['bearer_status']:
        result['reason'] = 'owned-bearer-error'
    elif item[3] not in (1, 2):
        result['reason'] = 'owned-bearer-inactive'
    elif not result['pdp_matches_setup']:
        result['reason'] = 'pdp-changed'
    elif any(result[f'{family}_present'] != result[f'setup_{family}_present']
             or result[f'{family}_present'] and not result[f'{family}_matches_setup']
             for family in ('ipv4', 'ipv6')):
        result['reason'] = 'address-changed'
    return result
