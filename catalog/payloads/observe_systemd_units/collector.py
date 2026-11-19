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
    def run(args):
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
            if code:
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
        if unit not in request['allowed_units'] or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit):
            raise ValueError('unit is outside operator allowlist')
    result = {'scope': scope}
    view, kind, state = request['view'], request['unit_type'], request['state']
    if view not in ('loaded', 'installed') or kind not in ('service', 'socket', 'timer', 'target', 'mount', 'path', 'slice') or state not in ('all', 'active', 'inactive', 'failed'):
        raise ValueError('invalid inventory selection')
    if view == 'installed' and state != 'all':
        raise ValueError('installed files do not have active state; select all')
    args = ['list-units' if view == 'loaded' else 'list-unit-files', '--all', '--type=' + kind, '--no-legend', '--plain']
    if view == 'loaded' and state != 'all':
        args.append('--state=' + state)
    pattern = request['unit_pattern']
    if not re.fullmatch(r'[A-Za-z0-9_@.*:-]{1,128}', pattern):
        raise ValueError('invalid operator inventory pattern')
    args.extend(['--', pattern])
    result['unit_pattern'] = pattern
    rows = []
    for line in run(args).splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 4 if view == 'loaded' else 2)
        if view == 'loaded':
            if len(fields) not in (4, 5):
                raise ValueError('malformed loaded-unit inventory record')
            keys = ('unit', 'load', 'active', 'sub', 'description')
        else:
            if len(fields) not in (2, 3):
                raise ValueError('malformed installed-unit inventory record')
            keys = ('unit_file', 'state', 'preset')
        rows.append(dict(zip(keys, fields)))
    if not isinstance(rows, list) or len(rows) > 256:
        raise ValueError('inventory exceeds 256 entries')
    keys = ('unit', 'load', 'active', 'sub', 'description') if view == 'loaded' else ('unit_file', 'state', 'preset')
    entries = [{key: text(row[key], 1024) for key in keys if key in row and row[key] is not None} for row in rows]
    result.update(view=view, unit_type=kind, state=state, units=entries)
    result['source_count'] = len(rows)
    result['truncated'] = len(rows) > 8
    result['units'] = result['units'][:8]
    while len(json.dumps(result, separators=(',', ':')).encode('utf-8')) > 3800 and result['units']:
        result['units'].pop()
        result['truncated'] = True
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
