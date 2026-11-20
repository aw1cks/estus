import estus_runtime
def main():
    import json, os, re, time
    request = estus_runtime.request()[0]
    scope = request['manager_scope']
    if scope not in ('system', 'user'):
        raise ValueError('unsupported operator manager scope')
    env = dict(os.environ, LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
    if scope == 'user':
        env['XDG_RUNTIME_DIR'] = '/run/user/' + str(os.getuid())
    collection_deadline = time.monotonic() + 20
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
        if not isinstance(unit, str) or not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,128}', unit) or (isinstance(allowed, list) and allowed and '*' not in allowed and unit not in allowed):
            raise ValueError('unit is outside operator allowlist')
    result = {'scope': scope}
    forward = ['Requires', 'Wants', 'Requisite', 'BindsTo', 'PartOf', 'Upholds', 'Before', 'After', 'Triggers']
    reverse = ['RequiredBy', 'WantedBy', 'RequisiteOf', 'BoundBy', 'ConsistsOf', 'UpheldBy', 'Before', 'After', 'TriggeredBy']
    direction, depth = request['direction'], request['depth']
    if direction not in ('forward', 'reverse') or type(depth) is not int or not 1 <= depth <= 3:
        raise ValueError('invalid relationship traversal')
    fields = forward if direction == 'forward' else reverse
    frontier, seen, edges = [(unit, 0)], {unit}, []
    while frontier:
        source, level = frontier.pop(0)
        if level >= depth:
            continue
        for relation, value in show(source, fields).items():
            for target in value.split():
                text(target, 256)
                edges.append({'source': source, 'relation': relation, 'target': target, 'depth': level + 1})
                if len(edges) > 256:
                    raise ValueError('relationship bound exceeded')
                if target not in seen:
                    seen.add(target)
                    if len(seen) > 64:
                        raise ValueError('relationship traversal bound exceeded')
                    frontier.append((target, level + 1))
    result.update(unit=unit, direction=direction, depth=depth, relationships=edges)
    result['truncated'] = len(result['relationships']) > 16
    result['relationships'] = result['relationships'][:16]
    while len(json.dumps(result, separators=(',', ':')).encode('utf-8')) > 3800 and result['relationships']:
        result['relationships'].pop()
        result['truncated'] = True
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == "__main__":
    main()
