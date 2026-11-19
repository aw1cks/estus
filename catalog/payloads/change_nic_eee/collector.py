import json
import os
import re
import selectors
import subprocess
import sys
import time


# ethtool 7.1 netlink/eee.c: status is configuration/negotiation, tx-lpi
# exists only when LPI is enabled; an absent hidden timer is never zero.
def parse_eee(text, interface='model0'):
    if not isinstance(text, str) or len(text) > 65536 or len(text.encode('utf8')) > 65536:
        raise ValueError('EEE output exceeded bound')

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate EEE JSON key')
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError('nonfinite EEE JSON value')

    try:
        data = json.loads(text, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, RecursionError) as error:
        raise ValueError('malformed EEE JSON') from error
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise ValueError('single EEE interface required')
    row = data[0]
    required = {'ifname', 'status', 'supported-eee-link-modes',
                'advertised-eee-link-modes', 'link-partner-advertised-eee-link-modes'}
    if not required <= set(row) or set(row) - required - {'tx-lpi'}:
        raise ValueError('EEE fields unavailable or unknown')
    if interface != 'model0' or row['ifname'] != interface:
        raise ValueError('EEE interface mismatch')
    status = row['status']
    if not isinstance(status, str) or status not in ('disabled', 'inactive', 'active'):
        raise ValueError('EEE capability unavailable or status unknown')
    result = {'enabled': status != 'disabled', 'active': status == 'active',
              'tx_lpi_enabled': 'tx-lpi' in row}
    if 'tx-lpi' in row:
        timer = row['tx-lpi']
        if type(timer) is not int or not 0 <= timer <= 4294967295:
            raise ValueError('EEE timer invalid')
        result['tx_lpi_timer_us'] = timer
    for source, field in (
        ('supported-eee-link-modes', 'supported_modes'),
        ('advertised-eee-link-modes', 'advertised_modes'),
        ('link-partner-advertised-eee-link-modes', 'peer_modes'),
    ):
        modes = row[source]
        if not isinstance(modes, list) or len(modes) > 16:
            raise ValueError('EEE mode array invalid')
        if any(not isinstance(mode, str) or not re.fullmatch(r'[A-Za-z0-9_/.+-]{1,64}', mode) for mode in modes):
            raise ValueError('EEE mode invalid')
        if len(set(modes)) != len(modes):
            raise ValueError('duplicate EEE mode')
        result[field] = modes
    if not result['supported_modes']:
        raise ValueError('EEE capability unavailable')
    if not set(result['advertised_modes']) <= set(result['supported_modes']):
        raise ValueError('EEE advertised modes outside supported modes')
    return result


def run(args):
    proc = subprocess.Popen(
        ['/usr/bin/ethtool'] + args,
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


def identity(p, policy):
    dev = p['interface']
    if dev != 'model0' or policy['interface'] != dev or policy['mac'] != '52:54:00:12:34:5a' or policy['driver'] != 'estus_nic_model':
        raise ValueError('interface outside synthetic model operator policy')
    base = '/sys/class/net/' + dev
    with open(base + '/address') as stream:
        address = stream.read(65)
    if len(address) > 64 or address.strip() != policy['mac']:
        raise ValueError('interface identity mismatch')
    driver = os.path.basename(os.path.realpath(base + '/device/driver', strict=True))
    if driver != policy['driver']:
        raise ValueError('driver outside reviewed policy')
    return dev, driver


def emit(result):
    raw = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(raw.encode('utf8')) > 4096:
        raise ValueError('projection bound exceeded')
    print(raw)


def main():
    p = json.loads(sys.argv[1])
    policy = json.loads(sys.argv[2])
    if policy.get('allow_runtime_tuning') is not True or os.geteuid() != 0:
        raise ValueError('fixed privileged operator runtime tuning policy required')
    if not isinstance(p, dict) or set(p) != {'interface', 'enabled', 'tx_lpi_timer_us'}:
        raise ValueError('closed EEE input required')
    enabled, timer = p['enabled'], p['tx_lpi_timer_us']
    if type(enabled) is not bool or type(timer) is not int or not 0 <= timer <= 1000000:
        raise ValueError('EEE configuration outside reviewed bounds')
    dev, driver = identity(p, policy)

    def observe():
        return parse_eee(run(['--json', '--show-eee', dev]), dev)

    def matches(state):
        return (state['enabled'] == enabled and state['tx_lpi_enabled'] is True
                and state.get('tx_lpi_timer_us') == timer)

    before = observe()
    changed = not matches(before)
    if changed:
        # One attempt only: failures may have partial effects. Never replay or roll back.
        run(['--set-eee', dev, 'eee', 'on' if enabled else 'off',
             'tx-lpi', 'on', 'tx-timer', str(timer)])
        after = observe()
        if not matches(after):
            raise ValueError('EEE mutation readback mismatch; partial effects possible, no automatic recovery')
    else:
        after = before
    emit({'interface': dev, 'driver': driver, 'scope': 'software_model',
          'before': before, 'after': after, 'changed': changed,
          'verified': True, 'persistence': 'runtime_only'})


if __name__ == '__main__':
    main()
