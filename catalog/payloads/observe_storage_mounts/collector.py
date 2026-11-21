import datetime
import json
import os
import sys

import estus_runtime

PROJECTION_BOUND = 4096
MAX_NODES = 256
MAX_MOUNTS = 256
MOUNT_FIELDS = [
    'mount',
    'device',
    'fstype',
    'size_total',
    'size_available',
    'inode_total',
    'inode_available',
]


def node_count(value):
    if isinstance(value, dict):
        return 1 + sum(node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(node_count(item) for item in value)
    return 1


def unescape_octal(value):
    out = []
    index = 0
    while index < len(value):
        if value[index] == '\\' and index + 3 < len(value) and value[index + 1:index + 4].isdigit():
            try:
                out.append(chr(int(value[index + 1:index + 4], 8)))
            except ValueError:
                out.append(value[index])
        else:
            out.append(value[index])
        index += 1
    return ''.join(out)


def main():
    # /proc/mounts is a symlink and the runtime reads with O_NOFOLLOW.
    data = estus_runtime.read_bytes('/proc/self/mounts', maximum=262144, optional=True)
    if data is None:
        print(json.dumps({'estus_error': {'code': 'unsupported_platform'}}))
        sys.exit(1)
    rows = []
    for line in data.decode('utf-8', 'strict').splitlines():
        columns = line.split()
        if len(columns) < 3:
            continue
        rows.append((unescape_octal(columns[1]), unescape_octal(columns[0]), columns[2]))
    if len(rows) > MAX_MOUNTS:
        rows = rows[:MAX_MOUNTS]

    unavailable = []
    mounts = []
    for mount, device, fstype in rows:
        record = {'mount': mount, 'device': device, 'fstype': fstype}
        try:
            status = os.statvfs(mount)
        except OSError:
            for field in ('size_total', 'size_available', 'inode_total', 'inode_available'):
                unavailable.append(mount + '.' + field)
        else:
            record['size_total'] = status.f_blocks * status.f_frsize
            record['size_available'] = status.f_bavail * status.f_frsize
            record['inode_total'] = status.f_files
            record['inode_available'] = status.f_favail
        mounts.append(record)

    result = {
        'source': 'proc mounts',
        'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'unavailable': unavailable,
        'mounts': mounts,
        'truncated': False,
        'omitted_records': 0,
    }
    while True:
        encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode('utf-8')) <= PROJECTION_BOUND and node_count(result) <= MAX_NODES:
            break
        if not mounts:
            raise ValueError('selected record exceeds projection budget')
        mounts.pop()
        result['truncated'] = True
        result['omitted_records'] += 1
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))


if __name__ == '__main__':
    main()
