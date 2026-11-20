import datetime
import json
import os
import sys

import estus_runtime

MAX_INTEGER = 9007199254740991
PROJECTION_BOUND = 16384
MAX_ITEMS = 1024
MAX_OFFSET = 65536
MAX_LIMIT = 100
BACKENDS = [
    ('apt', ('/usr/bin/dpkg-query', '/bin/dpkg-query'), ['-W', '-f', '${Package}\\t${Version}\\t${Architecture}\\t${binary:Package}\\n']),
    ('rpm', ('/usr/bin/rpm', '/bin/rpm'), ['-qa', '--qf', '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n']),
    ('apk', ('/sbin/apk', '/usr/sbin/apk', '/usr/bin/apk'), ['info', '-v']),
]
PROJECTION_FIELDS = ('name', 'version', 'architecture', 'source')


def bounded_text(value, maximum=4096):
    if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
        raise ValueError('invalid or oversized selected string')
    return value


def run(executable, arguments):
    return estus_runtime.run_or_exit(
        [executable] + arguments, timeout=30, max_bytes=8388608)['stdout']


def parse_packages(backend, raw):
    packages = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        columns = apk_columns(line) if backend == 'apk' else line.split('\t')
        if len(columns) < 3:
            continue
        name, version, architecture = columns[0].strip(), columns[1].strip(), columns[2].strip()
        if not name or not version:
            continue
        packages.append({
            'name': bounded_text(name, maximum=128),
            'version': bounded_text(version, maximum=256),
            'architecture': bounded_text(architecture or 'unknown', maximum=64),
            'source': backend,
        })
        if len(packages) > 262144:
            raise ValueError('package inventory exceeds bound')
    return packages


def apk_columns(line):
    version = ''
    name = line.strip()
    separator = line.find(' ')
    if separator >= 0:
        name = line[:separator].strip()
        version = line[separator + 1:].strip()
    return [name, version or 'unknown', 'unknown', 'apk']


def select_backend():
    for backend, candidates, arguments in BACKENDS:
        for executable in candidates:
            if os.path.isfile(executable) and os.access(executable, os.X_OK):
                return backend, executable, arguments
    return None


def main():
    request = estus_runtime.request()[0]
    offset = request.get('offset', 0)
    limit = request.get('limit', 50)
    name_filter = request.get('name')
    if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_OFFSET:
        raise ValueError('invalid offset')
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError('invalid limit')
    if name_filter is not None:
        name_filter = bounded_text(name_filter, maximum=64)

    selected = select_backend()
    if selected is None:
        print(json.dumps({'estus_error': {'code': 'dependency_unavailable'}}))
        sys.exit(1)
    backend, executable, arguments = selected

    packages = parse_packages(backend, run(executable, arguments))
    if name_filter is not None:
        packages = [entry for entry in packages if name_filter in entry['name']]
    packages.sort(key=lambda entry: (entry['name'], entry['version'], entry['architecture']))
    total = len(packages)
    page = packages[offset:offset + limit]

    result = {
        'backend': backend,
        'packages': page,
        'offset': offset,
        'total': total,
        'truncated': offset + len(page) < total,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if result['offset'] > MAX_INTEGER or result['total'] > MAX_INTEGER:
        raise ValueError('integer outside projection bound')
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
