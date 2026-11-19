import json
import os
import re
import selectors
import subprocess
import sys
import time


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
    proc = subprocess.Popen(
        [os.environ['ESTUS_EXEC_ETHTOOL']] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'},
    )
    sel = selectors.DefaultSelector()
    data = {}
    try:
        for stream in (proc.stdout, proc.stderr):
            sel.register(stream, selectors.EVENT_READ)
            data[stream] = bytearray()
        end = time.monotonic() + 6
        while sel.get_map():
            if time.monotonic() >= end:
                raise ValueError('ethtool deadline exceeded')
            for key, _ in sel.select(.1):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                data[key.fileobj].extend(chunk)
                if len(data[key.fileobj]) > 65536:
                    raise ValueError('ethtool output exceeded bound')
        rc = proc.wait(timeout=max(.01, end - time.monotonic()))
        if rc:
            raise ValueError('ethtool failed: ' + bytes(data[proc.stderr])[:1024].decode('utf8', 'replace'))
        return bytes(data[proc.stdout]).decode('utf8')
    finally:
        sel.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
        proc.stderr.close()


def main():
    p = json.loads(sys.argv[1])
    policy = json.loads(sys.argv[2])
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
    driver = os.path.basename(os.path.realpath(base + '/device/driver', strict=True))
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
