import estus_runtime
def main():
    import json, os, pwd, re, stat
    request = estus_runtime.request()[0]
    scope = request['manager_scope']
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    env = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
    if scope == 'user':
        env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
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
        if not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit) or (not estus_runtime.allowed(unit, allowed)):
            raise ValueError('unit is outside operator allowlist')
    result = {'scope': scope}
    paths = show(unit, ['FragmentPath', 'DropInPaths'])
    fragment, dropins = paths.get('FragmentPath', ''), paths.get('DropInPaths', '').split()
    if not fragment or len(dropins) > 16:
        raise ValueError('missing fragment or drop-in count exceeded')
    files = []
    config_roots = ('/etc/systemd/', '/run/systemd/', '/usr/lib/systemd/', '/lib/systemd/')
    if scope == 'user':
        config_roots += (pwd.getpwuid(os.getuid()).pw_dir + '/.config/systemd/user/',
                         '/run/user/' + str(os.getuid()) + '/systemd/')
    for kind, path in [('fragment', fragment)] + [('drop_in', p) for p in dropins]:
        if chr(92) in path or not path.startswith(config_roots):
            raise ValueError('unit config path outside approved systemd roots')
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError('unit configuration is not a regular file')
            data = stream.read(2049)
        if len(data) > 2048:
            raise ValueError('unit config source exceeds 2048 bytes')
        files.append({'kind': kind, 'path': text(path, 1024), 'content': data.decode('utf-8', 'strict')})
    result.update(unit=unit, sensitive=True, files=files)
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
