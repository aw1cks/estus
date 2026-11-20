def main():
    import json, os, re, sys, datetime
    unavailable = []

    def read(path, limit=4096):
        try:
            with open(path, 'rb') as f:
                data = f.read(limit + 1)
        except OSError:
            return None
        if len(data) > limit:
            raise ValueError('source bound')
        return data.decode().strip()

    def publish(data, source):
        result = dict(
            source=source,
            observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            unavailable=unavailable,
            **data
        )
        counters = result['counters']
        truncated = bool(result.get('truncated'))
        omitted = int(result.get('omitted_records', 0))
        total = int(result.get('total_counters', len(counters)))

        def nodes(v):
            if isinstance(v, dict):
                return 1 + sum(nodes(x) for x in v.values())
            if isinstance(v, list):
                return 1 + sum(nodes(x) for x in v)
            return 1

        while True:
            result['truncated'] = truncated
            result['omitted_records'] = omitted
            result['total_counters'] = total
            out = json.dumps(result, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            if len(out.encode()) <= 16384 and nodes(result) <= 1024:
                break
            # Return a whole-record prefix, never trim strings or unknown metadata.
            if not counters:
                raise ValueError('selected record exceeds projection budget')
            counters.pop()
            truncated = True
            omitted += 1
        print(out)

    import subprocess, selectors, time

    def run(argv, bound=1048576):
        p = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
        )
        sel = selectors.DefaultSelector()
        data = {}
        for f in (p.stdout, p.stderr):
            sel.register(f, selectors.EVENT_READ)
            data[f] = bytearray()
        end = time.monotonic() + 6
        try:
            while sel.get_map():
                if time.monotonic() > end:
                    raise TimeoutError('command timeout')
                for key, _ in sel.select(.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    data[key.fileobj].extend(chunk)
                    if len(data[key.fileobj]) > bound:
                        raise ValueError('command output bound')
            rc = p.wait(timeout=max(.1, end - time.monotonic()))
            return rc, bytes(data[p.stdout]).decode('utf-8', 'replace'), bytes(data[p.stderr]).decode('utf-8', 'replace')
        finally:
            if p.poll() is None:
                p.kill()
            p.wait()
            sel.close()
            p.stdout.close()
            p.stderr.close()

    interface = sys.argv[1]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', interface):
        raise ValueError('interface')
    filter_text = ''
    if len(sys.argv) > 2:
        filter_text = json.loads(sys.argv[2]) or ''
    if not isinstance(filter_text, str) or len(filter_text) > 64 or '\x00' in filter_text:
        raise ValueError('filter')
    if not os.path.isdir('/sys/class/net/' + interface):
        print(json.dumps({'estus_error': {'code': 'target_not_found'}}))
        sys.exit(1)
    rc, text, error = run([os.environ['ESTUS_EXEC_ETHTOOL'], '-S', interface])
    counters = []
    supported = rc == 0
    if rc == 0:
        for line in text.splitlines():
            m = re.fullmatch(r'\s*([A-Za-z0-9_.:-]{1,128}):\s*([0-9]+)\s*', line)
            if m:
                counters.append({'name': m[1], 'value': int(m[2])})
    else:
        combined = (text + error).lower()
        tolerated = (
            'no stats available',
            'not supported',
            'cannot get',
            'operation not permitted',
        )
        if not any(x in combined for x in tolerated):
            raise ValueError('statistics query failed')
        supported = False
        counters = []
        unavailable.append('driver_statistics')
    if filter_text:
        needle = filter_text.lower()
        counters = [c for c in counters if needle in c['name'].lower()]
    total_counters = len(counters)
    truncated = False
    omitted_records = 0
    if total_counters > 256:
        counters = counters[:256]
        truncated = True
        omitted_records = total_counters - len(counters)
    publish(
        {
            'interface': interface,
            'supported': supported,
            'counters': counters,
            'total_counters': total_counters,
            'truncated': truncated,
            'omitted_records': omitted_records,
        },
        'ethtool -S driver cumulative counters; not rates',
    )


if __name__ == "__main__":
    main()
