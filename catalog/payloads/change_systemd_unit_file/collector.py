import json
import os
import re

import estus_runtime

OPERATIONS = ['enable', 'disable', 'mask', 'unmask']
PROPERTIES = ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result']
UNIT_FILE_STATES = [
    'enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias',
    'static', 'indirect', 'disabled', 'generated', 'transient',
    'masked', 'masked-runtime',
]
UNIT_PATTERN = re.compile(r'[A-Za-z0-9_@.:-]{1,128}')
PROJECTION_BOUND = 4096


def unit_allowed(unit, allowed):
    if UNIT_PATTERN.fullmatch(unit or '') is None:
        return False
    return estus_runtime.allowed(unit, allowed)


def systemctl(scope, args, accepted=(0,)):
    executable = os.environ.get('ESTUS_EXEC_SYSTEMCTL')
    if not executable:
        raise ValueError('systemctl is unavailable')
    result = estus_runtime.run_bounded(
        [executable, '--' + scope, '--no-pager', '--no-ask-password'] + args,
        timeout=20,
        max_bytes=262144,
        accepted=accepted,
    )
    if result['returncode'] not in accepted:
        raise ValueError('systemctl failed with exit ' + str(result['returncode']))
    return result['stdout']


def show(scope, unit):
    raw = systemctl(scope, ['show', '--property=' + ','.join(PROPERTIES), '--', unit])
    properties = {}
    for line in raw.splitlines():
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
    operation = request.get('operation')
    if operation not in OPERATIONS or not estus_runtime.allowed(operation, request.get('allowed_operations')):
        raise ValueError('operation is outside operator policy')

    systemctl(scope, [operation, '--no-reload', '--', unit])
    file_state = systemctl(scope, ['is-enabled', '--', unit], (0, 1)).strip()
    if file_state not in UNIT_FILE_STATES:
        raise ValueError('unsupported unit-file state readback')
    result = {
        'scope': scope,
        'operation': operation,
        'operation_completed': True,
        'health': 'not_checked',
        'unit': unit,
        'properties': show(scope, unit),
        'manager_reload_performed': False,
        'manager_reload_required': True,
    }
    result['properties']['UnitFileState'] = file_state
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
