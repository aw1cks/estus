import datetime
import json
import os
import sys

import estus_runtime

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
# Projection field -> sysfs attribute below the block device directory.
# sysfs `size` counts 512-byte sectors regardless of the logical block size.
SYSFS_ATTRIBUTES = {
    'model': 'device/model',
    'vendor': 'device/vendor',
    'sectors': 'size',
    'sectorsize': 'queue/logical_block_size',
    'rotational': 'queue/rotational',
    'removable': 'removable',
    'scheduler_mode': 'queue/scheduler',
    'support_discard': 'queue/discard_max_bytes',
    'start': 'start',
}
PROJECTION_BOUND = 4096
MAX_NODES = 256
MAX_DEVICES = 256
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
    # sysfs `holders` and `slaves` are directories of device links, not files.
    try:
        entries = sorted(os.listdir(base + '/' + attribute))
    except FileNotFoundError:
        return None
    if len(entries) > 256:
        raise ValueError('entry bound')
    return [estus_runtime.check_text(entry, maximum=4096) for entry in entries]


def read_field(base, field):
    if field == 'size':
        sectors = read_value(base, 'size')
        return None if sectors is None else str(int(sectors) * 512)
    return read_value(base, SYSFS_ATTRIBUTES[field])


def describe(base, name, unavailable, with_partitions):
    record = {'name': name, 'partitions': []}
    for field in DEVICE_FIELDS:
        if field in ('holders', 'masters'):
            value = read_list(base, 'holders') if field == 'holders' else read_list('/sys/class/block/' + name, 'slaves')
        else:
            value = read_field(base, field)
        if value is None:
            unavailable.append(name + '.' + field)
        else:
            record[field] = value
    if not with_partitions:
        return record
    partition_root = base + '/'
    try:
        entries = sorted(os.listdir(partition_root))
    except OSError:
        entries = []
    if len(entries) > MAX_PARTITIONS:
        raise ValueError('partition bound')
    for entry in entries:
        partition_base = partition_root + entry
        if not os.path.isdir(partition_base) or not os.path.exists(partition_base + '/partition'):
            continue
        partition = {'name': entry}
        for field in PARTITION_FIELDS:
            if field == 'holders':
                value = read_list(partition_base, 'holders')
            else:
                value = read_field(partition_base, field)
            if value is None:
                unavailable.append(entry + '.' + field)
            else:
                partition[field] = value
        record['partitions'].append(partition)
    return record


def main():
    unavailable = []
    if not os.path.isdir('/sys/block'):
        print(json.dumps({'estus_error': {'code': 'unsupported_platform'}}))
        sys.exit(1)
    names = sorted(os.listdir('/sys/block'))
    if len(names) > MAX_DEVICES:
        raise ValueError('device bound')
    devices = []
    for name in names:
        base = '/sys/block/' + name
        if not os.path.isdir(base):
            continue
        devices.append(describe(base, name, unavailable, True))

    result = {
        'source': 'sysfs block devices',
        'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'unavailable': unavailable,
        'devices': devices,
        'truncated': False,
        'omitted_records': 0,
    }
    check(result, devices)
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))


def check(result, devices):
    while True:
        encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode('utf-8')) <= PROJECTION_BOUND and node_count(result) <= MAX_NODES:
            return
        if not devices:
            raise ValueError('selected record exceeds projection budget')
        devices.pop()
        result['truncated'] = True
        result['omitted_records'] += 1


if __name__ == '__main__':
    main()
