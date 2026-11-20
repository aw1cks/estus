import datetime
import json
import os
import re
import sys

import estus_runtime

DEVICE_PATTERN = re.compile(r'[A-Za-z0-9_.-]{1,64}')
DEVICE_FIELDS = [
    'model',
    'vendor',
    'size',
    'sectors',
    'sectorsize',
    'rotational',
    'removable',
    'scheduler_mode',
    'support_discard',
    'holders',
    'masters',
]
PARTITION_FIELDS = ['sectors', 'sectorsize', 'size', 'start', 'holders']
PROJECTION_BOUND = 4096
MAX_NODES = 256
MAX_PARTITIONS = 256


def node_count(value):
    if isinstance(value, dict):
        return 1 + sum(node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(node_count(item) for item in value)
    return 1


def read_value(base, attribute):
    data = estus_runtime.read_bytes(base + '/' + attribute, maximum=4096, optional=True)
    if data is None:
        return None
    return estus_runtime.check_text(data.decode('utf-8', 'strict').strip(), maximum=4096)


def read_list(base, attribute):
    data = estus_runtime.read_bytes(base + '/' + attribute, maximum=8192, optional=True)
    if data is None:
        return None
    entries = []
    for entry in data.decode('utf-8', 'strict').splitlines():
        entry = entry.strip()
        if not entry:
            continue
        entries.append(estus_runtime.check_text(entry, maximum=4096))
        if len(entries) > 256:
            raise ValueError('entry bound')
    return entries


def describe(name, unavailable):
    base = '/sys/class/block/' + name
    record = {'name': name, 'partitions': []}
    for field in DEVICE_FIELDS:
        if field == 'holders':
            value = read_list(base, 'holders')
        elif field == 'masters':
            value = read_list(base, 'slaves')
        else:
            value = read_value(base, field)
        if value is None:
            unavailable.append(name + '.' + field)
        else:
            record[field] = value
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        entries = []
    if len(entries) > MAX_PARTITIONS:
        raise ValueError('partition bound')
    for entry in entries:
        partition_base = base + '/' + entry
        if not os.path.isdir(partition_base) or not os.path.exists(partition_base + '/partition'):
            continue
        partition = {'name': entry}
        for field in PARTITION_FIELDS:
            if field == 'holders':
                value = read_list(partition_base, 'holders')
            else:
                value = read_value(partition_base, field)
            if value is None:
                unavailable.append(entry + '.' + field)
            else:
                partition[field] = value
        record['partitions'].append(partition)
    return record


def main():
    request = json.loads(sys.argv[1])
    name = request.get('device')
    if not isinstance(name, str) or DEVICE_PATTERN.fullmatch(name) is None:
        raise ValueError('invalid device selector')
    if not os.path.isdir('/sys/class/block/' + name):
        print(json.dumps({'estus_error': {'code': 'target_not_found'}}))
        sys.exit(1)

    unavailable = []
    result = {
        'source': 'sysfs block devices',
        'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'unavailable': unavailable,
        'device': describe(name, unavailable),
        'truncated': False,
        'omitted_records': 0,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND or node_count(result) > MAX_NODES:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
