import json
import os
import re

import estus_runtime

PROPERTIES = [
    'Id',
    'LoadState',
    'ActiveState',
    'SubState',
    'UnitFileState',
    'MainPID',
    'Result',
    'InvocationID',
    'NRestarts',
    'ActiveEnterTimestampMonotonic',
    'InactiveEnterTimestampMonotonic',
]
UNIT_PATTERN = re.compile(r'[A-Za-z0-9_@.:-]{1,128}')
PROJECTION_BOUND = 4096


def unit_allowed(unit, allowed):
    if UNIT_PATTERN.fullmatch(unit or '') is None:
        return False
    return estus_runtime.allowed(unit, allowed)


def show(scope, unit):
    executable = os.environ.get('ESTUS_EXEC_SYSTEMCTL')
    if not executable:
        raise ValueError('systemctl is unavailable')
    result = estus_runtime.run_bounded(
        [
            executable,
            '--' + scope,
            '--no-pager',
            '--no-ask-password',
            'show',
            '--property=' + ','.join(PROPERTIES),
            '--',
            unit,
        ],
        timeout=20,
        max_bytes=262144,
    )
    if result['returncode'] != 0:
        raise ValueError('systemctl failed with exit ' + str(result['returncode']))
    properties = {}
    for line in result['stdout'].splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or key in properties:
            raise ValueError('unexpected selected property')
        properties[key] = estus_runtime.check_text(value, maximum=4096)
    return properties


def main():
    request = estus_runtime.request()[0]
    scope = request.get('manager_scope')
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    unit = request.get('unit')
    if not unit_allowed(unit, request.get('allowed_units')):
        raise ValueError('unit is outside operator policy')

    properties = show(scope, unit)
    result = {
        'scope': scope,
        'properties': properties,
        'unavailable': [name for name in PROPERTIES if name not in properties],
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
