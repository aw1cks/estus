def parse_fec(text):
    if not isinstance(text, str) or len(text) > 65536 or len(text.encode('utf8')) > 65536:
        raise ValueError('FEC output exceeds bound')
    labels = {
        'Supported/Configured FEC encodings': 'configured',
        'Active FEC encoding': 'active',
    }
    modes = {'None': 'none', 'Off': 'off', 'Auto': 'auto', 'RS': 'rs', 'BaseR': 'baser', 'LLRS': 'llrs'}
    fields = {}
    for line in text.splitlines():
        label, sep, value = line.strip().partition(':')
        if not sep or label not in labels:
            continue
        field = labels[label]
        if field in fields:
            raise ValueError('duplicate FEC field')
        tokens = value.split()
        if not tokens or any(token not in modes for token in tokens):
            raise ValueError('unknown or missing FEC encoding')
        parsed = [modes[token] for token in tokens]
        if len(set(parsed)) != len(parsed):
            raise ValueError('duplicate FEC encoding')
        if field == 'active':
            if len(parsed) != 1:
                raise ValueError('ambiguous active FEC encoding')
            fields[field] = parsed[0]
        else:
            fields[field] = parsed
    if set(fields) != {'configured', 'active'}:
        raise ValueError('FEC capability unavailable')
    return fields


def main():
    import json
    import os
    import re
    import selectors
    import subprocess
    import sys
    import time

    p = json.loads(sys.argv[1])
    policy = json.loads(sys.argv[2])
    if policy.get('allow_runtime_tuning') is not True or os.geteuid() != 0:
        raise ValueError('fixed privileged operator runtime tuning policy required')
    if not isinstance(p, dict) or set(p) != {'interface', 'mode'}:
        raise ValueError('closed FEC input required')
    dev = p['interface']
    mode = p['mode']
    if not isinstance(dev, str) or dev != policy['interface'] or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', dev) or mode not in ('off', 'rs') or mode not in policy['modes']:
        raise ValueError('FEC request outside operator policy')
    base = '/sys/class/net/' + dev
    with open(base + '/address') as source:
        mac = source.read(65)
    if len(mac) > 64 or mac.strip() != policy['mac']:
        raise ValueError('interface identity mismatch')
    driver_link = base + '/device/driver'
    if not os.path.islink(driver_link):
        raise ValueError('sysfs driver identity unavailable')
    driver = os.path.basename(os.path.realpath(driver_link))
    if driver != policy['driver']:
        raise ValueError('driver outside reviewed policy')

    def run(args):
        proc = subprocess.Popen(
            [os.environ['ESTUS_EXEC_ETHTOOL']] + args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'},
        )
        sel = selectors.DefaultSelector()
        data = {}
        end = time.monotonic() + 6
        try:
            for stream in (proc.stdout, proc.stderr):
                sel.register(stream, selectors.EVENT_READ)
                data[stream] = bytearray()
            while sel.get_map():
                if time.monotonic() >= end:
                    raise ValueError('ethtool deadline exceeded; mutation may have applied, no automatic recovery')
                for key, _ in sel.select(.1):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        sel.unregister(key.fileobj)
                        continue
                    data[key.fileobj].extend(chunk)
                    if len(data[key.fileobj]) > 65536:
                        raise ValueError('ethtool output exceeded bound; mutation may have applied, no automatic recovery')
            rc = proc.wait(timeout=max(.01, end - time.monotonic()))
            if rc:
                detail = bytes(data[proc.stderr])[:1024].decode('utf8', 'replace')
                raise ValueError('ethtool failed; mutation may have applied, no automatic recovery: ' + detail)
            return bytes(data[proc.stdout]).decode('utf8')
        finally:
            sel.close()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()

    def observe():
        return parse_fec(run(['--show-fec', dev]))

    before = observe()
    expected = {'configured': [mode], 'active': mode}
    changed = before != expected
    if changed:
        run(['--set-fec', dev, 'encoding', mode])
        after = observe()
        if after != expected:
            raise ValueError('FEC mutation readback mismatch; partial effects possible, no automatic recovery')
    else:
        after = before
    result = {
        'interface': dev,
        'driver': driver,
        'before': before,
        'after': after,
        'changed': changed,
        'verified': True,
        'persistence': 'runtime_only',
    }
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(raw.encode('utf8')) > 4096:
        raise ValueError('projection bound exceeded')
    print(raw)


if __name__ == '__main__':
    main()
