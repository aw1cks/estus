import datetime
import json
import os
import platform
import re
import sys

import estus_runtime

MAX_INTEGER = 9007199254740991
UNKNOWN = ('', 'na', 'none', 'unknown', 'not specified', 'not available', 'default string', 'to be filled by o.e.m.')
UNAVAILABLE_FIELDS = [
    'distribution',
    'distribution_version',
    'boot_id',
    'uptime_seconds',
    'virtualization_type',
    'virtualization_role',
]
UPTIME_PATTERN = re.compile(r'[0-9]+(?:\.[0-9]+)?[ \t]+[0-9]+(?:\.[0-9]+)?')


def text(value, maximum=4096):
    return estus_runtime.check_text(value, maximum=maximum)


def read_text(path, maximum=4096):
    data = estus_runtime.read_bytes(path, maximum=maximum, optional=True)
    if data is None:
        return None
    try:
        return data.decode('utf-8', 'strict').strip()
    except UnicodeDecodeError:
        return None


def meaningful(value):
    if value is None:
        return False
    return value.strip().lower() not in UNKNOWN


def os_release():
    distribution = None
    version = None
    data = estus_runtime.read_bytes('/etc/os-release', maximum=8192, optional=True)
    if data is None:
        return distribution, version
    values = {}
    for line in data.decode('utf-8', 'replace').splitlines():
        key, separator, value = line.partition('=')
        if not separator:
            continue
        values[key.strip()] = value.strip().strip('"').strip("'")
    distribution = values.get('NAME') or None
    version = values.get('VERSION_ID') or None
    if not meaningful(distribution):
        distribution = values.get('ID') if meaningful(values.get('ID')) else None
    if not meaningful(version):
        version = values.get('VERSION') if meaningful(values.get('VERSION')) else None
    return distribution, version


def uptime_seconds():
    data = estus_runtime.read_bytes('/proc/uptime', maximum=128, optional=True)
    if data is None:
        return None
    raw = data.decode('ascii', 'strict').strip()
    if UPTIME_PATTERN.fullmatch(raw) is None:
        raise ValueError('malformed proc uptime')
    seconds = float(raw.split()[0])
    if seconds < 0 or seconds > MAX_INTEGER:
        raise ValueError('proc uptime outside supported range')
    return int(seconds)


def virtualization():
    kind = None
    role = None
    product = read_text('/sys/class/dmi/id/product_name', maximum=256) or ''
    vendor = read_text('/sys/class/dmi/id/sys_vendor', maximum=256) or ''
    hypervisor_visible = read_text('/sys/class/dmi/id/product_name', maximum=256) is not None
    cpuinfo = read_text('/proc/cpuinfo', maximum=262144) or ''
    flags = ''
    for line in cpuinfo.splitlines():
        if line.startswith('flags') or line.startswith('Features'):
            flags = line.partition(':')[2]
            break
    tokens = set(flags.split())
    if not hypervisor_visible and not tokens:
        return kind, role
    combined = (vendor + ' ' + product).lower()
    candidates = [
        ('kvm', ('kvm', 'qemu', 'red hat', 'oVirt')),
        ('vmware', ('vmware',)),
        ('virtualbox', ('virtualbox', 'innotek')),
        ('microsoft', ('microsoft', 'hyper-v', 'virtual machine')),
        ('xen', ('xen',)),
        ('docker', ('docker',)),
        ('lxc', ('lxc',)),
        ('powervm', ('powervm',)),
    ]
    for name, needles in candidates:
        if any(needle.lower() in combined for needle in needles):
            kind = name
            role = 'guest'
            break
    if kind is None and 'hypervisor' in tokens:
        kind = 'kvm'
        role = 'guest'
    if kind is None and tokens and 'hypervisor' not in tokens:
        kind = 'none'
        role = 'host'
    return kind, role


def main():
    if platform.system() != 'Linux':
        print(json.dumps({'estus_error': {'code': 'unsupported_platform'}}))
        sys.exit(1)
    uname = os.uname()
    observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    unavailable = []

    result = {
        'system': 'Linux',
        'kernel': text(uname.release, maximum=256),
        'architecture': text(uname.machine, maximum=64),
        'observed_at': text(observed_at, maximum=32),
        'scope': 'ssh_process_view',
    }

    distribution, version = os_release()
    if distribution is None:
        unavailable.append('distribution')
    else:
        result['distribution'] = text(distribution, maximum=128)
    if version is None:
        unavailable.append('distribution_version')
    else:
        result['distribution_version'] = text(version, maximum=128)

    try:
        boot = estus_runtime.boot_id()
    except (OSError, ValueError):
        unavailable.append('boot_id')
    else:
        result['boot_id'] = boot

    seconds = uptime_seconds()
    if seconds is None:
        unavailable.append('uptime_seconds')
    else:
        result['uptime_seconds'] = seconds

    kind, role = virtualization()
    if kind is None:
        unavailable.append('virtualization_type')
    else:
        result['virtualization_type'] = text(kind, maximum=64)
    if role is None:
        unavailable.append('virtualization_role')
    else:
        result['virtualization_role'] = role

    result['unavailable'] = unavailable
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
