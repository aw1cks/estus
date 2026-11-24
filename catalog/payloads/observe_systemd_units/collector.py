import estus_runtime

MAX_ENTRIES = 256


def page_inventory(result, rows, offset, budget=3800):
    """Fill one page of inventory rows starting at offset within the byte budget.

    Rows past MAX_ENTRIES are dropped only for the '*' pattern (truncated stays
    true on every page); narrower patterns fail closed. next_offset is present
    while later rows remain, and a row that cannot fit an empty page fails
    instead of returning a page that would never advance.
    """
    import json
    if type(offset) is not int or not 0 <= offset < MAX_ENTRIES:
        raise ValueError('offset out of bounds')
    capped = False
    if len(rows) > MAX_ENTRIES:
        if result['unit_pattern'] != '*':
            raise ValueError('inventory exceeds 256 entries')
        rows = rows[:MAX_ENTRIES]
        capped = True
    page = dict(result, units=[], source_count=len(rows), offset=offset, truncated=True)
    for row in rows[offset:]:
        page['units'].append(row)
        if len(json.dumps(page, separators=(',', ':')).encode('utf-8')) > budget:
            page['units'].pop()
            if not page['units']:
                raise ValueError('inventory entry exceeds projection bound')
            break
    end = offset + len(page['units'])
    if end < len(rows):
        page['next_offset'] = end
    page['truncated'] = capped or end < len(rows)
    return page


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
    def text(value, maximum=4096):
        if not isinstance(value, str) or len(value) > maximum:
            raise ValueError('invalid or oversized selected property')
        return value
    def show(unit, properties):
        raw = run(['show', '--property=' + ','.join(properties), '--', unit])
        result = {}
        for line in raw.splitlines():
            key, separator, value = line.partition('=')
            if not separator or key not in properties or key in result:
                raise ValueError('unexpected selected property')
            result[key] = text(value)
        return result
    if 'unit' in request:
        unit = request['unit']
        allowed = request.get('allowed_units')
        if not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit) or (not estus_runtime.allowed(unit, allowed)):
            raise ValueError('unit is outside operator allowlist')
    result = {'scope': scope}
    view, kind, state = request['view'], request['unit_type'], request['state']
    if view not in ('loaded', 'installed') or kind not in ('service', 'socket', 'timer', 'target', 'mount', 'path', 'slice') or state not in ('all', 'active', 'inactive', 'failed'):
        raise ValueError('invalid inventory selection')
    if view == 'installed' and state != 'all':
        raise ValueError('installed files do not have active state; select all')
    args = ['list-units' if view == 'loaded' else 'list-unit-files', '--all', '--type=' + kind, '--no-legend', '--plain']
    if view == 'loaded' and state != 'all':
        args.append('--state=' + state)
    pattern = request['unit_pattern']
    if not re.fullmatch(r'[A-Za-z0-9_@.*:-]{1,128}', pattern):
        raise ValueError('invalid operator inventory pattern')
    args.extend(['--', pattern])
    result['unit_pattern'] = pattern
    rows = []
    for line in run(args).splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 4 if view == 'loaded' else 2)
        if view == 'loaded':
            if len(fields) not in (4, 5):
                raise ValueError('malformed loaded-unit inventory record')
            keys = ('unit', 'load', 'active', 'sub', 'description')
        else:
            if len(fields) not in (2, 3):
                raise ValueError('malformed installed-unit inventory record')
            keys = ('unit_file', 'state', 'preset')
        rows.append(dict(zip(keys, fields)))
    if not isinstance(rows, list):
        raise ValueError('invalid inventory rows')
    keys = ('unit', 'load', 'active', 'sub', 'description') if view == 'loaded' else ('unit_file', 'state', 'preset')
    entries = [{key: text(row[key], 1024) for key in keys if key in row and row[key] is not None} for row in rows]
    result.update(view=view, unit_type=kind, state=state)
    result = page_inventory(result, entries, request['offset'])
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
