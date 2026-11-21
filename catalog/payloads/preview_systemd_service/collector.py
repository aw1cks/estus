import json
import os
import re

import estus_runtime

PROPERTIES = ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result']
UNIT_PATTERN = re.compile(r'[A-Za-z0-9_@.:-]{1,128}')
OPERATIONS = ('start', 'stop', 'restart', 'reload', 'enable', 'disable', 'mask', 'unmask')
PROJECTION_BOUND = 4096


def unit_allowed(unit, allowed):
    if UNIT_PATTERN.fullmatch(unit or '') is None:
        return False
    return estus_runtime.allowed(unit, allowed)


def systemctl(scope, args):
    executable = os.environ.get('ESTUS_EXEC_SYSTEMCTL')
    if not executable:
        raise ValueError('systemctl is unavailable')
    result = estus_runtime.run_bounded(
        [executable, '--' + scope, '--no-pager', '--no-ask-password'] + args,
        timeout=20,
        max_bytes=262144,
    )
    if result['returncode'] != 0:
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


def predicts_change(operation, properties):
    active = properties.get('ActiveState', '')
    unit_file = properties.get('UnitFileState', '')
    if operation == 'start':
        return active != 'active'
    if operation == 'stop':
        return active not in ('inactive', 'failed')
    if operation in ('restart', 'reload'):
        return True
    if operation == 'enable':
        return unit_file != 'enabled'
    if operation == 'disable':
        return unit_file != 'disabled'
    if operation == 'mask':
        return unit_file != 'masked'
    if operation == 'unmask':
        return unit_file == 'masked'
    raise ValueError('unsupported systemd preview operation')


def main():
    request = estus_runtime.request()[0]
    scope = request.get('manager_scope')
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    unit = request.get('unit')
    if not unit_allowed(unit, request.get('allowed_units')):
        raise ValueError('unit is outside operator policy')
    operation = request.get('operation')
    if operation not in OPERATIONS:
        raise ValueError('unsupported systemd preview operation')

    properties = show(scope, unit)
    result = {
        'scope': scope,
        'unit': unit,
        'operation': operation,
        'changed': predicts_change(operation, properties),
        'current_properties': properties,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
