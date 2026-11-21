import estus_runtime
def slice_message_text(raw):
    if isinstance(raw, list) and all(type(x) is int and 0 <= x <= 255 for x in raw):
        return bytes(raw).decode('utf-8', 'replace')
    if isinstance(raw, str):
        return raw
    raise ValueError('unsupported journal message encoding')


def build_journal_item(r, boot, max_int=9007199254740991):
    import re
    def integer(key):
        v = r[key]
        if not isinstance(v, str) or not re.fullmatch('[0-9]{1,16}', v):
            raise ValueError('invalid journal integer')
        n = int(v)
        if n > max_int:
            raise ValueError('journal integer bound')
        return n
    msg = slice_message_text(r.get('MESSAGE', ''))
    item = {
        'cursor': r['__CURSOR'],
        'boot_id': r['_BOOT_ID'],
        'realtime_usec': integer('__REALTIME_TIMESTAMP'),
        'monotonic_usec': integer('__MONOTONIC_TIMESTAMP'),
        'message': msg[:512],
        'message_truncated': len(msg) > 512,
    }
    if len(item['cursor']) > 256 or item['boot_id'] != boot:
        raise ValueError('unexpected journal identity')
    for src, dst, bound in [('_SYSTEMD_UNIT', 'unit', 256), ('_TRANSPORT', 'transport', 32)]:
        if src in r:
            if not isinstance(r[src], str) or len(r[src]) > bound:
                raise ValueError('journal field bound')
            item[dst] = r[src]
    if 'PRIORITY' in r:
        item['priority'] = integer('PRIORITY')
        if item['priority'] > 7:
            raise ValueError('priority bound')
    return item, msg


def select_journal_records(
    raw_records,
    boot,
    limit,
    since,
    until,
    priority,
    scope,
    status='available',
    contains='',
    direction='backward',
    cursor_arg='',
    skip_cursor='',
    max_bytes=131072,
):
    import json
    if direction not in ('backward', 'forward'):
        raise ValueError('invalid direction')
    if '\x00' in contains or len(contains) > 128:
        raise ValueError('invalid contains filter')

    incomplete_reason = 'retained accessible journal only; history may expire; concurrent writes are not atomic'
    base_payload = {
        'boot_id': boot,
        'scope': scope,
        'status': status,
        'records': [],
        'continuation_cursor': cursor_arg,
        'truncated': False,
        'incomplete': True,
        'incomplete_reason': incomplete_reason,
        'since': since,
        'until': until,
        'priority_max': priority,
    }
    if status != 'available':
        return base_payload

    seen_anchor = not bool(skip_cursor and direction == 'backward')
    result = []
    truncated = False
    for r in raw_records:
        if not seen_anchor:
            if r.get('__CURSOR') == skip_cursor:
                seen_anchor = True
            continue
        if skip_cursor and r.get('__CURSOR') == skip_cursor:
            continue
        item, full_msg = build_journal_item(r, boot)
        # With a cursor journalctl cannot also take --since, so the lower bound
        # is enforced here: older records end a backward page, and are skipped
        # when paging forward.
        if item['realtime_usec'] < since * 1000000:
            if direction == 'backward':
                break
            continue
        if contains and contains not in full_msg:
            continue
        if len(result) >= limit:
            truncated = True
            break
        candidate_records = result + [item]
        candidate_payload = dict(base_payload)
        candidate_payload['records'] = candidate_records
        candidate_payload['continuation_cursor'] = f"{direction}:{candidate_records[-1]['cursor']}"
        candidate_payload['truncated'] = True
        encoded_len = len(json.dumps(candidate_payload, separators=(',', ':'), allow_nan=False).encode())
        if encoded_len > max_bytes:
            truncated = True
            break
        result = candidate_records

    payload = dict(base_payload)
    payload['records'] = result
    payload['continuation_cursor'] = f"{direction}:{result[-1]['cursor']}" if result else cursor_arg
    payload['truncated'] = truncated
    return payload


def parse_cursor_arg(cursor_arg, direction):
    import re
    if not cursor_arg:
        return ''
    if cursor_arg.startswith('backward:'):
        if direction != 'backward':
            raise ValueError('cursor direction mismatch')
        raw = cursor_arg[len('backward:'):]
    elif cursor_arg.startswith('forward:'):
        if direction != 'forward':
            raise ValueError('cursor direction mismatch')
        raw = cursor_arg[len('forward:'):]
    else:
        raw = cursor_arg
    if not raw or not re.fullmatch(r'[A-Za-z0-9=;_-]{1,256}', raw):
        raise ValueError('invalid bounded cursor syntax')
    return raw


def main():
    import os, json, re
    args = estus_runtime.request()

    def read(path, bound=65536):
        with open(path, 'rb') as f:
            data = f.read(bound + 1)
        if len(data) > bound:
            raise ValueError('source exceeds bound')
        return data.decode('utf-8', errors='strict').strip()

    def run(argv, bound=8388608):
        return estus_runtime.run_bounded(
            argv, timeout=20, max_bytes=bound)['stdout']

    def publish(value):
        encoded = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(encoded.encode()) > 131072:
            raise ValueError('result bound')
        print(encoded)

    p = dict(
        zip(
            ['unit', 'boot_id', 'since', 'until', 'priority', 'cursor', 'limit', 'contains', 'direction'],
            args,
        )
    )

    if p['since'] > p['until']:
        raise ValueError('inverted time interval')
    if not (1 <= p['limit'] <= 500):
        raise ValueError('limit out of bounds')
    direction = p['direction'] or 'backward'
    contains = p['contains'] or ''
    raw_cursor = parse_cursor_arg(p['cursor'] or '', direction)

    boot = p['boot_id']
    if boot == 'current':
        boot = read('/proc/sys/kernel/random/boot_id', 128).replace('-', '')
    if not re.fullmatch('[0-9a-f]{32}', boot):
        raise ValueError('invalid boot')

    unit = p['unit']
    if unit is not None and (not isinstance(unit, str) or not unit or len(unit) > 128 or '\x00' in unit):
        raise ValueError('invalid unit')
    scope = 'approved_system_unit' if unit else 'system_journal'

    base = [os.environ['ESTUS_EXEC_JOURNALCTL'], '--no-pager', '--quiet', '--output=json', '--all']

    def fetch_records(argv, max_lines):
        text = run(argv)
        lines = text.splitlines()
        if len(lines) > max_lines:
            raise ValueError('record count exceeds bound')
        return [json.loads(line) for line in lines]

    status = 'available'
    raw_records = []
    if raw_cursor:
        # journalctl seeks to the nearest entry for a cursor it no longer holds
        # and pages on silently; confirm the exact entry still exists first.
        try:
            probe = fetch_records(base + ['--cursor=' + raw_cursor, '--lines=+1'], 1)
        except estus_runtime.CommandFailed as error:
            if 'Failed to seek to cursor' not in str(error):
                raise
            probe = []
        if not probe or probe[0].get('__CURSOR') != raw_cursor:
            status = 'cursor_unavailable'
    if status == 'available':
        fetch_limit = 2000 if contains else p['limit'] + 1

        query = base + ['--boot=' + boot, '--priority=0..' + str(p['priority'])]
        if direction == 'forward':
            query += ['--until=@' + str(p['until']), '--lines=+' + str(fetch_limit)]
            if raw_cursor:
                query += ['--after-cursor=' + raw_cursor]
            else:
                query += ['--since=@' + str(p['since'])]
        else:
            query += [
                '--until=@' + str(p['until']),
                '--reverse',
                '--lines=' + str(fetch_limit),
            ]
            # journalctl accepts only one of --since/--cursor/--after-cursor;
            # with a cursor the lower time bound is applied at selection.
            if raw_cursor:
                query += ['--after-cursor=' + raw_cursor]
            else:
                query += ['--since=@' + str(p['since'])]
        if unit:
            query += ['_SYSTEMD_UNIT=' + unit]
        try:
            raw_records = fetch_records(query, fetch_limit + 1)
        except estus_runtime.CommandFailed as error:
            if raw_cursor and 'Failed to seek to cursor' in str(error):
                status = 'cursor_unavailable'
            else:
                raise

    # A backward page is fetched with --after-cursor, which already excludes the
    # anchor record; only forward paging can still echo it in the window.
    skip_cursor = raw_cursor if direction == 'forward' else ''
    payload = select_journal_records(
        raw_records,
        boot=boot,
        limit=p['limit'],
        since=p['since'],
        until=p['until'],
        priority=p['priority'],
        scope=scope,
        status=status,
        contains=contains,
        direction=direction,
        cursor_arg=p['cursor'] or '',
        skip_cursor=skip_cursor,
        max_bytes=131072,
    )
    publish(payload)


if __name__ == '__main__':
    main()
