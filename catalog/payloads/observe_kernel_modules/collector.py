import estus_runtime


def page_modules(result, observed, offset, budget=3900, max_nodes=256):
    """Fill one name-sorted page from offset to the projection budget.

    next_offset is present while modules remain; a module that cannot fit an
    empty page fails instead of returning a page that never advances.
    """
    import json
    if type(offset) is not int or not 0 <= offset <= 512:
        raise ValueError('invalid module page offset')
    page = dict(result, modules=[], total_count=len(observed))
    def nodes(v):
        if isinstance(v, dict): return 1 + sum(nodes(x) for x in v.values())
        if isinstance(v, list): return 1 + sum(nodes(x) for x in v)
        return 1
    for module in observed[offset:]:
        page['modules'].append(module)
        # next_offset and observed_at are added after paging; reserve their bytes and items.
        if len(json.dumps(page, separators=(',', ':')).encode('utf-8')) > budget or nodes(page) + 2 > max_nodes:
            page['modules'].pop()
            if not page['modules']:
                raise ValueError('module record exceeds projection budget')
            break
    end = offset + len(page['modules'])
    if end < len(observed):
        page['next_offset'] = end
    return page


def main():
    import datetime, json, platform, re
    if platform.system() != 'Linux':
        raise ValueError('requires Linux')
    a = estus_runtime.request()[0]
    def read(path, maximum=4096, optional=False):
        try:
            with open(path, 'rb') as f:
                b = f.read(maximum + 1)
        except (FileNotFoundError, PermissionError):
            if optional:
                return None
            raise
        if len(b) > maximum:
            raise ValueError('source read exceeds bound')
        return b

    result = {'boot_id':estus_runtime.boot_id(), 'source':'Linux procfs/sysfs; installed target utilities', 'unavailable':[]}
    def modules():
        rows = read('/proc/modules', 262144).decode('ascii').splitlines()
        if len(rows) > 512:
            raise ValueError('module list exceeds bound')
        values = []
        for line in rows:
            p = line.split()
            if len(p) < 6 or not re.fullmatch(r'[A-Za-z0-9_]+', p[0]):
                raise ValueError('malformed loaded module record')
            size, refs = int(p[1]), int(p[2])
            if not 0 <= size <= 9007199254740991 or not 0 <= refs <= 9007199254740991:
                raise ValueError('module integer outside range')
            holders = p[3].strip(',').split(',') if p[3] != '-' else []
            if len(holders) > 128:
                raise ValueError('holders exceed bound')
            values.append({'name':estus_runtime.check_text(p[0],64), 'size_bytes':size, 'references':refs,
                'holders':[estus_runtime.check_text(h,64) for h in holders], 'state':estus_runtime.check_text(p[4],32)})
        return values

    offset = a['offset']
    observed = sorted(modules(), key=lambda row: row['name'])
    result['scope'] = 'name-sorted live procfs pages; concurrent module changes can shift offsets'
    result = page_modules(result, observed, offset)

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
