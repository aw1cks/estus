import json
import os
import re
import estus_runtime


SOURCE = 'ethtool --show-fec; driver-reported configuration and active encoding, not wire-level proof'


def parse_fec(text):
    if not isinstance(text, str) or len(text) > 65536 or len(text.encode('utf8')) > 65536:
        raise ValueError('FEC output exceeded bound')
    labels = {
        'Supported/Configured FEC encodings': 'configured',
        'Active FEC encoding': 'active',
    }
    modes = {'None': 'none', 'Off': 'off', 'Auto': 'auto', 'RS': 'rs', 'BaseR': 'baser', 'LLRS': 'llrs'}
    result = {}
    for line in text.splitlines():
        label, sep, value = line.strip().partition(':')
        if not sep or label not in labels:
            continue
        field = labels[label]
        if field in result:
            raise ValueError('duplicate FEC field')
        tokens = value.split()
        if not tokens or any(token not in modes for token in tokens):
            raise ValueError('missing or unknown FEC encoding')
        selected = [modes[token] for token in tokens]
        if len(set(selected)) != len(selected):
            raise ValueError('duplicate FEC encoding')
        if field == 'active':
            if len(selected) != 1:
                raise ValueError('ambiguous active FEC encoding')
            result[field] = selected[0]
        else:
            result[field] = selected
    if set(result) != {'configured', 'active'}:
        raise ValueError('selected driver FEC capability unavailable')
    return result


def run(args):
    return estus_runtime.run_bounded(
        [os.environ['ESTUS_EXEC_ETHTOOL']] + args, timeout=6, max_bytes=65536)['stdout']


def main():
    p = estus_runtime.request()[0]
    policy = estus_runtime.request()[1]
    if not isinstance(p, dict) or set(p) != {'interface'}:
        raise ValueError('unexpected FEC input')
    dev = p['interface']
    if not isinstance(dev, str) or dev != policy['interface'] or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', dev):
        raise ValueError('interface outside operator policy')
    base = '/sys/class/net/' + dev
    with open(base + '/address') as stream:
        address = stream.read(65)
    if len(address) > 64 or address.strip() != policy['mac']:
        raise ValueError('interface identity mismatch')
    link = base + '/device/driver'
    try:
        os.stat(link)
    except OSError:
        raise ValueError('driver link absent')
    driver = os.path.basename(os.path.realpath(link))
    if driver != policy['driver']:
        raise ValueError('driver outside reviewed policy')
    state = parse_fec(run(['--show-fec', dev]))
    result = {'interface': dev, 'driver': driver, **state, 'source': SOURCE}
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(raw.encode('utf8')) > 4096:
        raise ValueError('projection bound exceeded')
    print(raw)


if __name__ == '__main__':
    main()
