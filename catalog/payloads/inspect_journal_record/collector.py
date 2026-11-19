def message_utf8_bytes(raw):
    if isinstance(raw, list) and all(type(x) is int and 0 <= x <= 255 for x in raw):
        return bytes(raw)
    if isinstance(raw, str):
        return raw.encode('utf-8')
    raise ValueError('unsupported journal message encoding')


def slice_record_bytes(msg_bytes, offset, max_bytes):
    import base64
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise ValueError('invalid offset')
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not (1 <= max_bytes <= 4096):
        raise ValueError('invalid max_bytes')
    total_bytes = len(msg_bytes)
    start = min(offset, total_bytes)
    end = min(start + max_bytes, total_bytes)
    chunk = msg_bytes[start:end]
    return {
        'data_base64': base64.b64encode(chunk).decode('ascii'),
        'offset': offset,
        'next_offset': end,
        'total_bytes': total_bytes,
        'eof': end >= total_bytes,
    }


def read_journal_record_from_records(probe, boot, raw_cursor, offset, max_bytes):
    incomplete_reason = 'retained accessible journal only; a rotated or modified record is not a retained immutable artifact'
    if (
        not probe
        or probe[0].get('__CURSOR') != raw_cursor
        or probe[0].get('_BOOT_ID') != boot
    ):
        return {
            'boot_id': boot,
            'cursor': raw_cursor,
            'status': 'cursor_unavailable',
            'data_base64': '',
            'offset': offset,
            'next_offset': offset,
            'total_bytes': 0,
            'eof': True,
            'incomplete': True,
            'incomplete_reason': incomplete_reason,
        }
    msg_bytes = message_utf8_bytes(probe[0].get('MESSAGE', ''))
    sliced = slice_record_bytes(msg_bytes, offset, max_bytes)
    return {
        'boot_id': boot,
        'cursor': raw_cursor,
        'status': 'available',
        'data_base64': sliced['data_base64'],
        'offset': sliced['offset'],
        'next_offset': sliced['next_offset'],
        'total_bytes': sliced['total_bytes'],
        'eof': sliced['eof'],
        'incomplete': True,
        'incomplete_reason': incomplete_reason,
    }


def main():
    import os, sys, json, re, time, selectors, subprocess, signal
    args = [json.loads(x) for x in sys.argv[1:]]

    def read(path, bound=65536):
        with open(path, 'rb') as f:
            data = f.read(bound + 1)
        if len(data) > bound:
            raise ValueError('source exceeds bound')
        return data.decode('utf-8', errors='strict').strip()

    class UtilityError(ValueError):
        pass

    def run(argv, bound=4194304):
        p = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_COLORS': '0'},
            start_new_session=True,
        )
        streams = selectors.DefaultSelector()
        streams.register(p.stdout, selectors.EVENT_READ)
        streams.register(p.stderr, selectors.EVENT_READ)
        out = {p.stdout: bytearray(), p.stderr: bytearray()}
        deadline = time.monotonic() + 10
        try:
            while streams.get_map():
                if time.monotonic() > deadline:
                    raise ValueError('subprocess deadline')
                for key, _ in streams.select(.1):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        streams.unregister(key.fileobj)
                        continue
                    out[key.fileobj].extend(data)
                    if sum(map(len, out.values())) > bound:
                        raise ValueError('subprocess output bound')
            rc = p.wait(timeout=1)
            if rc:
                raise UtilityError(
                    'fixed utility failed: '
                    + str(rc)
                    + ': '
                    + bytes(out[p.stderr])[:512].decode('utf-8', 'replace')
                )
            return bytes(out[p.stdout]).decode('utf-8', 'strict')
        finally:
            streams.close()
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGKILL)
            p.wait()

    def publish(value):
        encoded = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode()) > 8192:
            raise ValueError('result bound')
        print(encoded)

    p = dict(zip(['boot_id', 'cursor', 'offset', 'max_bytes'], args))
    raw_cursor = p['cursor']
    if not raw_cursor or not re.fullmatch(r'[A-Za-z0-9=;_-]{1,256}', raw_cursor):
        raise ValueError('invalid bounded cursor syntax')

    boot = p['boot_id']
    if boot == 'current':
        boot = read('/proc/sys/kernel/random/boot_id', 128).replace('-', '')
    if not re.fullmatch('[0-9a-f]{32}', boot):
        raise ValueError('invalid boot')

    offset = p['offset']
    max_bytes = p['max_bytes']

    base = ['/usr/bin/journalctl', '--no-pager', '--quiet', '--output=json', '--all']
    probe = []
    try:
        text = run(base + ['--cursor=' + raw_cursor, '--lines=+1'])
        lines = text.splitlines()
        if len(lines) > 1:
            raise ValueError('record count exceeds bound')
        probe = [json.loads(line) for line in lines]
    except UtilityError as error:
        if 'Failed to seek to cursor' not in str(error):
            raise
        probe = []

    payload = read_journal_record_from_records(probe, boot, raw_cursor, offset, max_bytes)
    publish(payload)


if __name__ == '__main__':
    main()
