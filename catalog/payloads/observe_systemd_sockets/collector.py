import estus_runtime

MAX_ENTRIES = 256
PROPERTIES = ('Id', 'ActiveState', 'Triggers', 'Listen', 'Accept', 'NConnections', 'NAccepted')


def parse_show(raw):
    """Parse `systemctl show` for PROPERTIES; Listen repeats once per endpoint and becomes a list."""
    result = {'Listen': []}
    for line in raw.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or len(value) > 4096:
            raise ValueError('unexpected selected property')
        if key == 'Listen':
            if value:
                result['Listen'].append(value)
            if len(result['Listen']) > 64:
                raise ValueError('listen endpoint bound')
        elif key in result:
            raise ValueError('unexpected selected property')
        else:
            result[key] = value
    return result


def main():
    import json, os, re
    request = estus_runtime.request()[0]
    scope = request['manager_scope']
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    env = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
    if scope == 'user':
        env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
    base = [os.environ['ESTUS_EXEC_SYSTEMCTL'], '--' + scope, '--no-pager', '--no-ask-password']
    def run(args, accepted=(0,)):
        return estus_runtime.run_bounded(
            base + args, timeout=8, max_bytes=262144, accepted=accepted, env=env)['stdout']
    def show(unit):
        return parse_show(run(['show', '--property=' + ','.join(PROPERTIES), '--', unit]))
    if 'unit' in request:
        unit = request['unit']
        if unit not in request['allowed_units'] or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit):
            raise ValueError('unit is outside operator allowlist')
    offset = request['offset']
    if type(offset) is not int or not 0 <= offset < MAX_ENTRIES:
        raise ValueError('offset out of bounds')
    rows = []
    for line in run(['list-units', '--all', '--type=socket', '--no-legend', '--plain']).splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 4)
        if len(fields) not in (4, 5):
            raise ValueError('malformed activation-unit inventory record')
        if len(fields[0]) > 256:
            raise ValueError('invalid or oversized selected property')
        rows.append(fields[0])
    capped = len(rows) > MAX_ENTRIES
    rows = rows[:MAX_ENTRIES]
    # Only this page's units are queried; the budget decides where the page ends.
    page = {'scope': scope, 'sockets': [], 'source_count': len(rows), 'offset': offset, 'truncated': True}
    def nodes(v):
        if isinstance(v, dict): return 1 + sum(nodes(x) for x in v.values())
        if isinstance(v, list): return 1 + sum(nodes(x) for x in v)
        return 1
    for unit in rows[offset:]:
        page['sockets'].append(show(unit))
        # next_offset is added after paging; reserve its item (max_items is 256).
        if len(json.dumps(page, separators=(',', ':')).encode('utf-8')) > 3800 or nodes(page) + 1 > 256:
            page['sockets'].pop()
            if not page['sockets']:
                raise ValueError('socket entry exceeds projection bound')
            break
    end = offset + len(page['sockets'])
    if end < len(rows):
        page['next_offset'] = end
    page['truncated'] = capped or end < len(rows)
    encoded = json.dumps(page, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
