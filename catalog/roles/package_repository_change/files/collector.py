import json


def main(evidence):
    import json, sys
    approved_sources=json.loads(sys.argv[2])
    import datetime, json, os, re, subprocess, tempfile, time
    import apt

    def run(argv, timeout=12):
        # A regular temporary file bounds memory and rejects oversized command output.
        with tempfile.TemporaryFile() as out:
            proc = subprocess.Popen(argv, stdout=out, stderr=out, env=dict(os.environ, LC_ALL='C', DEBIAN_FRONTEND='noninteractive'))
            end = time.monotonic() + timeout
            while proc.poll() is None:
                if time.monotonic() > end or os.fstat(out.fileno()).st_size > 262144:
                    proc.kill(); proc.wait()
                    raise ValueError('command timed out/oversized; mutation may be uncertain; never replay automatically')
                time.sleep(.02)
            if os.fstat(out.fileno()).st_size > 262144:
                raise ValueError('command output exceeds bound')
            out.seek(0); text = out.read(262145).decode('utf-8', 'strict')
            if proc.returncode:
                raise ValueError('package command failed; do not replay: ' + text[:2048])
            return text

    def cache():
        c = apt.Cache()
        if len(c) > 100000:
            raise ValueError('package cache exceeds supported bound')
        return c

    def package(name):
        if name not in approved_packages or not re.fullmatch(r'[a-z0-9][a-z0-9+.-]{0,63}', name):
            raise ValueError('package outside reviewed allowlist')
        c = cache()
        if name not in c:
            raise ValueError('unknown package')
        return c[name]

    def freshness():
        # apt's success stamp is created only by the explicit refresh procedure.
        try:
            age = max(0, int(time.time() - os.stat('/var/lib/apt/periodic/update-success-stamp').st_mtime))
            return {'state': 'fresh' if age <= 86400 else 'stale', 'age_seconds': min(age, 9007199254740991)}
        except FileNotFoundError:
            return {'state':'unknown', 'age_seconds':None}
    request=json.loads(sys.argv[1])
    choice=request['repository']
    if choice not in ('primary','alternate'): raise ValueError('unknown reviewed repository')
    source=approved_sources[choice]
    if not source.startswith('deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-') or '\n' in source or 'trusted=' in source: raise ValueError('repository violates reviewed signature policy')
    path='/etc/apt/sources.list.d/estus-catalog.list'
    with open(path,'rb') as f: previous=f.read(4097)
    if len(previous)>4096: raise ValueError('source exceeds bound')
    content=(source+'\n').encode()
    fd, tmp=tempfile.mkstemp(prefix='.estus-',dir=os.path.dirname(path))
    try:
        with os.fdopen(fd,'wb') as f: f.write(content); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,0o644)
        if previous != content:
            evidence['changed'] = None
            os.replace(tmp,path)
            evidence['changed'] = True
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    with open(path,'rb') as f:
        if f.read(4097)!=content: raise ValueError('repository postcondition failed')
    try:
        os.unlink('/var/lib/apt/periodic/update-success-stamp')
        evidence['changed'] = True
    except FileNotFoundError: pass
    result={'repository':choice,'source':source,'signature_required':True,'changed':evidence['changed'],'refreshed':False}

    encoded=json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded)>4096: raise ValueError('result exceeds bound')
    evidence['changed'] = result.get('changed', evidence['changed'])
    print(encoded)


if __name__ == '__main__':
    evidence = {'changed': False}
    try:
        main(evidence)
    except Exception:
        # A failed command/postcondition is not a verified domain result.
        # null means an attempted mutation has no conclusive readback.
        print(json.dumps(evidence, separators=(',', ':')))
        raise SystemExit(1)
