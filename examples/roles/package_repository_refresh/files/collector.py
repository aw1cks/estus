import json


def main(evidence):
    import sys
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
            return {'state':'unknown'}
    request=json.loads(sys.argv[1])
    evidence['changed'] = None
    run(['/usr/bin/apt-get','-o','APT::Update::Error-Mode=any','-o','Acquire::Retries=0','-o','Acquire::http::Timeout=5','-o','Acquire::https::Timeout=5','-o','DPkg::Lock::Timeout=0','update'],25)
    c = cache()
    # Only publish freshness after apt has authenticated every configured source.
    os.makedirs('/var/lib/apt/periodic',exist_ok=True)
    with open('/var/lib/apt/periodic/update-success-stamp','w') as f: f.write('')
    evidence['changed'] = True
    result={'backend':'apt','refreshed':True,'cache':freshness(),'package_count':len(c)}

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
