import estus_runtime


def page_entries(result, observed, offset, budget=3900, max_nodes=256):
    """Fill one ID-sorted page from offset to the projection budget.

    next_offset is present while entries remain; an entry that cannot fit an
    empty page fails instead of returning a page that never advances.
    """
    import json
    if type(offset) is not int or not 0 <= offset <= 128:
        raise ValueError('invalid entry page offset')
    page = dict(result, entries=[], total_count=len(observed))
    def nodes(v):
        if isinstance(v, dict): return 1 + sum(nodes(x) for x in v.values())
        if isinstance(v, list): return 1 + sum(nodes(x) for x in v)
        return 1
    for entry in observed[offset:]:
        page['entries'].append(entry)
        # observed_at is added after paging; the budget leaves room for it.
        if len(json.dumps(page, separators=(',', ':')).encode('utf-8')) > budget or nodes(page) >= max_nodes:
            page['entries'].pop()
            if not page['entries']:
                raise ValueError('boot entry exceeds projection budget')
            break
    end = offset + len(page['entries'])
    if end < len(observed):
        page['next_offset'] = end
    return page


def main():
    import datetime, json, os, platform
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

    def run(argv):
        return estus_runtime.run_bounded(
            argv, timeout=12, max_bytes=262144, accepted=None,
            env={'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'})

    def checked(argv):
        return run(argv)['stdout']

    result = {'boot_id':estus_runtime.boot_id(), 'source':'Linux procfs/sysfs; installed target utilities', 'unavailable':[]}

    def entries():
        data = json.loads(checked([os.environ['ESTUS_EXEC_BOOTCTL'], '--json=short', '--no-pager', 'list']))
        if not isinstance(data, list) or len(data) > 128:
            raise ValueError('boot entry count exceeds bound')
        selected = []
        ids = set()
        for e in data:
            ident = estus_runtime.check_text(e.get('id'), 255)
            if not ident or ident in ids:
                raise ValueError('missing or duplicate exact entry ID')
            ids.add(ident)
            v = {'entry_id':ident, 'source':estus_runtime.check_text(e.get('source', 'unknown'), 128),
                 'type':estus_runtime.check_text(e.get('type', 'unknown'), 128), 'command_line_sensitive':True,
                 'unknown':[]}
            for key, alias in [('linux','linux'), ('efi','efi'), ('title','title'), ('path','path')]:
                if key in e:
                    v[alias] = estus_runtime.check_text(e[key], 2048)
                else:
                    v['unknown'].append(alias)
            if 'initrd' in e:
                if not isinstance(e['initrd'], list) or len(e['initrd']) > 16:
                    raise ValueError('initrd list exceeds bound')
                v['initrd'] = [estus_runtime.check_text(i, 2048) for i in e['initrd']]
            else:
                v['unknown'].append('initrd')
            selected.append((v, e))
        return selected

    offset = a['offset']
    observed = sorted([v for v,e in entries()], key=lambda row: row['entry_id'])
    result['scope'] = 'ID-sorted live bootctl pages; concurrent entry changes can shift offsets'
    result = page_entries(result, observed, offset)

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
