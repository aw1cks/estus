import estus_runtime
def main():
    import json, os, re, time
    request = estus_runtime.request()[0]
    scope = request['manager_scope']
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    env = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
    if scope == 'user':
        env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
    collection_deadline = time.monotonic() + 20
    base = [os.environ['ESTUS_EXEC_SYSTEMCTL'], '--' + scope, '--no-pager', '--no-ask-password']
    def run(args, accepted=(0,)):
        return estus_runtime.run_bounded(
            base + args, timeout=8, max_bytes=262144, accepted=accepted, env=env)['stdout']
    def text(value, maximum=4096):
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError('invalid or oversized selected property')
        return value
    def show(unit, properties):
        raw = run(['show', '--property=' + ','.join(properties), '--', unit])
        result = {}
        for line in raw.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in properties or key in result:
                raise ValueError('unexpected selected property')
            result[key] = text(value)
        return result
    if 'unit' in request:
        unit = request['unit']
        allowed = request.get('allowed_units')
        if not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit) or (isinstance(allowed, list) and allowed and '*' not in allowed and unit not in allowed):
            raise ValueError('unit is outside operator allowlist')
    result = {'scope': scope}
    limits = request['limits']
    if not isinstance(limits, dict) or not limits or set(limits) - {'memory_max_bytes', 'tasks_max', 'cpu_quota_percent'}:
        raise ValueError('invalid runtime limits')
    settings = []
    for key, prop, minimum, maximum, suffix in [('memory_max_bytes', 'MemoryMax', 16777216, 1099511627776, ''), ('tasks_max', 'TasksMax', 8, 65536, ''), ('cpu_quota_percent', 'CPUQuota', 1, 800, '%')]:
        if key in limits:
            value = limits[key]
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError('runtime limit outside approved range')
            settings.append(prop + '=' + str(value) + suffix)
    run(['set-property', '--runtime', '--', unit] + settings)
    result.update(requested_limits=limits, persistent=False)
    result.update(unit=unit, properties=show(unit, ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result', 'MemoryMax', 'TasksMax', 'CPUQuotaPerSecUSec']))
    result.update(operation='set_runtime_limits', operation_completed=True, health='not_checked')
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
