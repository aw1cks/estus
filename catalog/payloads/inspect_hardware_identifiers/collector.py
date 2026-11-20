import datetime
import json
import sys

import estus_runtime

UNKNOWN = ('', 'na', 'none', 'unknown', 'not specified', 'not available', 'default string', 'to be filled by o.e.m.', 'oem')
FIELDS = [
    ('product_serial', 'product_serial'),
    ('product_uuid', 'product_uuid'),
    ('board_serial', 'board_serial'),
    ('chassis_serial', 'chassis_serial'),
    ('chassis_asset_tag', 'chassis_asset_tag'),
]
PROJECTION_BOUND = 4096
MAX_NODES = 256


def node_count(value):
    if isinstance(value, dict):
        return 1 + sum(node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(node_count(item) for item in value)
    return 1


def main():
    unavailable = []
    values = {}
    for name, attribute in FIELDS:
        data = estus_runtime.read_bytes(
            '/sys/class/dmi/id/' + attribute, maximum=4096, optional=True
        )
        if data is None:
            unavailable.append(name)
            continue
        try:
            value = data.decode('utf-8', 'strict').strip()
        except UnicodeDecodeError:
            unavailable.append(name)
            continue
        if value.strip().lower() in UNKNOWN:
            unavailable.append(name)
            continue
        values[name] = estus_runtime.check_text(value, maximum=4096)

    result = {
        'source': 'sysfs dmi ids',
        'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'unavailable': unavailable,
        'values': values,
        'truncated': False,
        'omitted_records': 0,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND or node_count(result) > MAX_NODES:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
