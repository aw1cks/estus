import estus_runtime
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

    p = estus_runtime.request()[0]
    policy = estus_runtime.request()[1]
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
        return estus_runtime.run_bounded(
            [os.environ['ESTUS_EXEC_ETHTOOL']] + args, timeout=6, max_bytes=65536)['stdout']

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
