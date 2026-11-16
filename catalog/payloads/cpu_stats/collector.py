import datetime

import json

import os

import platform

import re

import sys

import time

import uuid

MAX_INTEGER = 9007199254740991

FIELDS = ('user', 'nice', 'system', 'idle', 'iowait', 'irq',
          'softirq', 'steal', 'guest', 'guest_nice')

def integer(text, maximum):
    if re.fullmatch(rb'[0-9]+', text) is None:
        raise ValueError('malformed unsigned CPU observation')
    value = int(text)
    if value > maximum:
        raise ValueError('CPU observation outside supported range')
    return value


def main():



    if platform.system() != 'Linux':
        raise ValueError('CPU observation requires Linux')
    limit = integer(sys.argv[1].encode('ascii'), 16)
    sample_ms = integer(sys.argv[2].encode('ascii'), 2000)
    if limit < 1:
        raise ValueError('topology limit must be positive')
    hz = os.sysconf('SC_CLK_TCK')
    if not isinstance(hz, int) or not 1 <= hz <= 1000000:
        raise ValueError('unsupported clock tick frequency')

    def read_optional(path):
        try:
            with open(path, 'rb', buffering=0) as stream:
                data = stream.read(128)
        except OSError:
            return None
        if len(data) == 128:
            raise ValueError('CPU observation exceeds read bound')
        return data.strip()

    def read_boot_id():
        data = read_optional('/proc/sys/kernel/random/boot_id')
        if data is None:
            return None
        text = data.decode('ascii')
        canonical = str(uuid.UUID(text))
        if text != canonical:
            raise ValueError('noncanonical boot identifier')
        return canonical

    def observe():
        counters = None
        cpu_ids = set()
        prefix_bytes = 0
        with open('/proc/stat', 'rb', buffering=4096) as stream:
            while True:
                line = stream.readline(4096)
                # Do not consume or parse the possibly huge interrupts row.
                if not line.startswith(b'cpu'):
                    break
                prefix_bytes += len(line)
                if not line.endswith(b'\n') or prefix_bytes > 262144:
                    raise ValueError('CPU counter prefix exceeds read bound')
                if counters is None:
                    parts = line.split()
                    if len(parts) != 11 or parts[0] != b'cpu':
                        raise ValueError('unsupported aggregate CPU counters')
                    counters = dict(zip(FIELDS, (integer(v, MAX_INTEGER)
                                                for v in parts[1:])))
                else:
                    match = re.match(rb'cpu([0-9]+)[ \t]', line)
                    if match is None:
                        raise ValueError('malformed CPU identifier row')
                    cpu_id = integer(match.group(1), 262143)
                    if cpu_id in cpu_ids or len(cpu_ids) >= 4096:
                        raise ValueError('duplicate or excessive CPU identifiers')
                    cpu_ids.add(cpu_id)
        if counters is None or not cpu_ids:
            raise ValueError('missing CPU counter observations')
        monotonic_ns = time.monotonic_ns()
        observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec='microseconds').replace('+00:00', 'Z')
        return counters, cpu_ids, monotonic_ns, observed_at, read_boot_id()

    first = observe()
    last = first
    result = {
        'system': 'Linux',
        'scope': 'procfs_sysfs_view',
        'clock_ticks_per_second': hz,
        'counters': first[0],
        'unavailable': [],
    }
    if sample_ms > 0:
        time.sleep(sample_ms / 1000)
        last = observe()
        elapsed = last[2] - first[2]
        if not 1 <= elapsed <= MAX_INTEGER:
            raise ValueError('sample elapsed time outside supported range')
        decreased = any(last[0][field] < first[0][field] for field in FIELDS)
        identity_changed = (first[1] != last[1] or
                            (first[4] is not None and last[4] is not None
                             and first[4] != last[4]))
        result.update(sample_elapsed_ns=elapsed, counters_end=last[0],
                      counter_decrease=decreased, identity_changed=identity_changed)
        if (first[4] is not None and first[4] == last[4]
                and first[1] == last[1] and not decreased):
            result['delta'] = {field: last[0][field] - first[0][field]
                               for field in FIELDS}
        else:
            result['unavailable'].append('delta')
    if last[4] is None:
        result['unavailable'].append('boot_id')
    if last[4] is not None:
        result['boot_id'] = last[4]
    result.update(observed_at=last[3], online_cpu_count=len(last[1]),
                  topology_truncated=len(last[1]) > limit)
    topology = []
    for cpu_id in sorted(last[1])[:limit]:
        row = {'cpu_id': cpu_id, 'unavailable': []}
        for field, filename in (('package_id', 'physical_package_id'),
                                ('core_id', 'core_id')):
            data = read_optional('/sys/devices/system/cpu/cpu{}/topology/{}'.format(
                cpu_id, filename))
            if data is None:
                row['unavailable'].append(field)
                continue
            if re.fullmatch(rb'-?[0-9]+', data) is None:
                raise ValueError('malformed topology identifier')
            value = int(data)
            if value < 0:
                row['unavailable'].append(field)
            elif value > 2147483647:
                raise ValueError('topology identifier outside supported range')
            else:
                row[field] = value
        topology.append(row)
    result['topology'] = topology
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))


if __name__ == "__main__":
    main()
