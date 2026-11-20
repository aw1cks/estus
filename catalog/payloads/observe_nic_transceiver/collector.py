import json
import math
import os
import re
import selectors
import subprocess
import sys
import time


SOURCE = 'synthetic SFF-8472 EEPROM decoded by real ethtool --json -m; software model, not physical optical measurements'


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate module JSON key')
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError('nonfinite module JSON number')


def parse_module(text):
    if not isinstance(text, str) or len(text) > 65536 or len(text.encode('utf8')) > 65536:
        raise ValueError('module output exceeded bound')
    try:
        decoded = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    except (RecursionError, json.JSONDecodeError) as exc:
        raise ValueError('malformed module JSON') from exc
    pending = [(decoded, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > 2048 or depth > 8:
            raise ValueError('module JSON structure exceeded bound')
        if isinstance(item, dict):
            pending.extend((value, depth + 1) for value in item.values())
        elif isinstance(item, list):
            pending.extend((value, depth + 1) for value in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('nonfinite module JSON number')
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
        raise ValueError('expected one decoded module')
    module = decoded[0]
    for key, expected in [('identifier', 3), ('extended_identifier', 4), ('optical_diagnostics_support', True)]:
        if type(module.get(key)) is not type(expected) or module[key] != expected:
            raise ValueError('selected SFP diagnostics unavailable')
    result = {}
    for field, key, approved in [('vendor', 'vendor_name', 'ESTUS TEST'), ('part', 'vendor_pn', 'SIM-SFP-1')]:
        value = module.get(key)
        if not isinstance(value, str) or not 1 <= len(value) <= 16 or value != approved:
            raise ValueError('module identity outside reviewed software model')
        result[field] = value
    rx = module.get('rx_power')
    if not isinstance(rx, dict) or rx.get('type') != 'Receiver signal average optical power':
        raise ValueError('selected receive power units unavailable')
    # The pinned JSON writer uses %g (six significant digits), not display precision.
    for field, value, low, high in [
        ('temperature_c', module.get('module_temperature_measurement'), -128, 127.996),
        ('voltage_v', module.get('module_voltage_measurement'), 0, 6.5535),
        ('tx_bias_ma', module.get('laser_tx_bias_current'), 0, 131.07),
        ('tx_power_mw', module.get('transmit_avg_optical_power'), 0, 6.5535),
        ('rx_power_mw', rx.get('value'), 0, 6.5535),
    ]:
        if type(value) not in (int, float) or not low <= value <= high or not math.isfinite(value):
            raise ValueError('selected module sensor unavailable or outside decoded bounds')
        result[field] = value
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
            raise ValueError('ethtool module read failed')
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
        raise ValueError('unexpected module input')
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
    state = parse_module(run(['--json', '-m', dev]))
    result = {'interface': dev, 'driver': driver, 'scope': 'software_model', **state, 'source': SOURCE}
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(raw.encode('utf8')) > 4096:
        raise ValueError('projection bound exceeded')
    print(raw)


if __name__ == '__main__':
    main()
