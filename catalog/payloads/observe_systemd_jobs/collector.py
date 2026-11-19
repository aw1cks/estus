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
    rows = []
    for line in run(['list-jobs', '--no-legend', '--plain']).splitlines():
        if not line.strip() or line.strip() == 'No jobs running.':
            continue
        fields = line.split()
        if len(fields) != 4 or not fields[0].isascii() or not fields[0].isdigit():
            raise ValueError('malformed job inventory record')
        rows.append(dict(zip(('job', 'unit', 'type', 'state'), (int(fields[0]), *fields[1:]))))
    if not isinstance(rows, list) or len(rows) > 128:
        raise ValueError('job bound exceeded')
    jobs = []
    for row in rows:
        job = row['job']
        if type(job) is not int or not 0 <= job <= 4294967295:
            raise ValueError('invalid job identifier')
        jobs.append({'job': job, 'unit': text(row['unit'], 256), 'type': text(row['type'], 32), 'state': text(row['state'], 32)})
    result['jobs'] = jobs
    result['source_count'] = len(rows)
    result['truncated'] = len(rows) > 8
    result['jobs'] = result['jobs'][:8]
    while len(json.dumps(result, separators=(',', ':')).encode('utf-8')) > 3800 and result['jobs']:
        result['jobs'].pop()
        result['truncated'] = True
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
