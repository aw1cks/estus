def main():
    import json, os, re, selectors, subprocess, sys, time
    request = json.loads(sys.argv[1])
    scope = request['manager_scope']
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    env = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
    if scope == 'user':
        env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
    collection_deadline = time.monotonic() + 20
    base = [os.environ['ESTUS_EXEC_SYSTEMCTL'], '--' + scope, '--no-pager', '--no-ask-password']
    def run(args, accepted=(0,)):
        process = subprocess.Popen(base + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        streams = selectors.DefaultSelector()
        streams.register(process.stdout, selectors.EVENT_READ, 'out')
        streams.register(process.stderr, selectors.EVENT_READ, 'err')
        buffers = {'out': bytearray(), 'err': bytearray()}
        deadline = min(time.monotonic() + 8, collection_deadline)
        try:
            while streams.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('systemctl deadline exceeded')
                for key, _ in streams.select(min(remaining, 0.2)):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        streams.unregister(key.fileobj)
                    else:
                        buffers[key.data].extend(chunk)
                        if len(buffers[key.data]) > (262144 if key.data == 'out' else 8192):
                            raise ValueError('systemctl output bound exceeded')
            code = process.wait(timeout=max(0.001, deadline - time.monotonic()))
            if code not in accepted:
                raise ValueError('systemctl failed with exit ' + str(code) + ': ' + buffers['err'].decode('utf-8', 'replace')[:2048])
            return buffers['out'].decode('utf-8', 'strict')
        finally:
            streams.close()
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()
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
    run(['disable', '--no-reload', '--', unit])
    file_state = run(['is-enabled', '--', unit], (0, 1)).strip()
    if file_state not in ('enabled', 'enabled-runtime', 'linked', 'linked-runtime', 'alias', 'static', 'indirect', 'disabled', 'generated', 'transient', 'masked', 'masked-runtime'):
        raise ValueError('unsupported unit-file state readback')
    result.update(unit=unit, properties=show(unit, ['Id', 'LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'Result']))
    result['properties']['UnitFileState'] = file_state
    result.update(manager_reload_performed=False, manager_reload_required=True)
    result.update(operation='disable', operation_completed=True, health='not_checked')
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()