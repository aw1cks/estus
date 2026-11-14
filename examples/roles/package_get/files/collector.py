def main():
    import json, sys
    approved_packages=json.loads(sys.argv[2])
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
    p = package(request['package'])
    if p.installed is None: raise ValueError('package not installed')
    files = run(['/usr/bin/dpkg-query','--listfiles',p.name]).splitlines()
    if len(files)>4096 or any(len(f)>1024 for f in files): raise ValueError('package file inventory exceeds bound')
    regular = next((f for f in files if os.path.isfile(f)), None)
    if regular is None: raise ValueError('no regular owned file available')
    owner = run(['/usr/bin/dpkg-query','--search',regular]).strip()
    if len(owner)>2048 or not any(line.split(': ',1)[0] == p.name for line in owner.splitlines()): raise ValueError('ownership postcondition failed')
    r = p.installed.record
    maintainer=r.get('Maintainer','')
    description=r.get('Description','')
    if len(maintainer)>512 or len(description)>2048: raise ValueError('package metadata exceeds supported bound')
    result = {'package':p.name,'version':p.installed.version,'architecture':p.installed.architecture,'maintainer':maintainer,'description':description,'files':files[:16],'files_total':len(files),'files_truncated':len(files)>16,'ownership':{'path':regular,'owner':p.name}}

    encoded=json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded)>4096: raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == '__main__':
    main()
