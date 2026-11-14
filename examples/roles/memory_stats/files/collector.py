import datetime

import json

import os

import platform

import re

import uuid

MAX_INTEGER = 9007199254740991

MEMORY_FIELDS = {
    b'MemTotal': 'mem_total_bytes',
    b'MemFree': 'mem_free_bytes',
    b'MemAvailable': 'mem_available_bytes',
    b'Buffers': 'buffers_bytes',
    b'Cached': 'cached_bytes',
    b'SwapTotal': 'swap_total_bytes',
    b'SwapFree': 'swap_free_bytes',
    b'Dirty': 'dirty_bytes',
    b'Writeback': 'writeback_bytes',
    b'Slab': 'slab_bytes',
    b'SReclaimable': 'sreclaimable_bytes',
    b'SUnreclaim': 'sunreclaim_bytes',
}

VM_FIELDS = {
    b'pgfault': 'page_faults',
    b'pgmajfault': 'major_page_faults',
    b'pswpin': 'swap_in_pages',
    b'pswpout': 'swap_out_pages',
    b'oom_kill': 'oom_kill_events',
    b'pgscan_kswapd': 'kswapd_scan_pages',
    b'pgscan_direct': 'direct_scan_pages',
}

def selected_values(data, fields, pattern, multiplier):
    if data is None:
        return {}
    lines = data.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    if len(lines) > 4096:
        raise ValueError('memory observation exceeds line count bound')
    values = {}
    for line in lines:
        key = re.split(rb'[: \t\r]', line.lstrip(b' \t'), maxsplit=1)[0]
        if key not in fields:
            continue
        if len(line) > 4096:
            raise ValueError('selected memory line exceeds read bound')
        match = re.fullmatch(pattern, line)
        if match is None or match.group(1) != key:
            raise ValueError('malformed selected memory observation')
        alias = fields[key]
        if alias in values:
            raise ValueError('duplicate selected memory observation')
        value = int(match.group(2)) * multiplier
        if value > MAX_INTEGER:
            raise ValueError('memory observation outside supported range')
        values[alias] = value
    return values


def parse_meminfo(data):
    if data is not None and len(data) > 131072:
        raise ValueError('memory source exceeds read bound')
    memory = selected_values(data, MEMORY_FIELDS,
        rb'([A-Za-z_]+):[ \t]+([0-9]+)[ \t]+kB[ \t]*', 1024)
    if 'mem_total_bytes' not in memory or 'mem_free_bytes' not in memory:
        raise ValueError('missing required memory gauges')
    return memory


def parse_vmstat(data):
    if data is not None and len(data) > 262144:
        raise ValueError('memory source exceeds read bound')
    return selected_values(data, VM_FIELDS,
        rb'([a-z_]+)[ \t]+([0-9]+)[ \t]*', 1)


def main():


    if platform.system() != 'Linux':
        raise ValueError('memory observation requires Linux')
    page_size = os.sysconf('SC_PAGE_SIZE')
    if not isinstance(page_size, int) or not 1 <= page_size <= 1048576:
        raise ValueError('unsupported page size')

    def read_proc(path, maximum, optional=False):
        try:
            with open(path, 'rb', buffering=4096) as stream:
                data = stream.read(maximum + 1)
        except OSError:
            if optional:
                return None
            raise
        if len(data) > maximum:
            raise ValueError('memory observation exceeds read bound')
        return data


    memory = parse_meminfo(read_proc('/proc/meminfo', 131072))
    counters = parse_vmstat(read_proc('/proc/vmstat', 262144, optional=True))
    unavailable = ['memory_bytes.' + alias for alias in MEMORY_FIELDS.values()
                   if alias not in memory]
    unavailable.extend('vm_counters.' + alias for alias in VM_FIELDS.values()
                       if alias not in counters)
    result = {
        'system': 'Linux',
        'scope': 'procfs_view',
        'page_size_bytes': page_size,
        'memory_bytes': memory,
        'vm_counters': counters,
        'unavailable': unavailable,
    }
    boot = read_proc('/proc/sys/kernel/random/boot_id', 128, optional=True)
    if boot is None:
        unavailable.append('boot_id')
    else:
        text = boot.decode('ascii').strip()
        canonical = str(uuid.UUID(text))
        if text != canonical:
            raise ValueError('noncanonical boot identifier')
        result['boot_id'] = canonical
    # Collection spans proc sources; this end timestamp is not an atomic snapshot.
    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec='microseconds').replace('+00:00', 'Z')
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))


if __name__ == "__main__":
    main()
