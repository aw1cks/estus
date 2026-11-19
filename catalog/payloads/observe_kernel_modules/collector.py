def main():
    import datetime, json, platform, re, sys, uuid
    if platform.system() != 'Linux':
        raise ValueError('requires Linux')
    a = json.loads(sys.argv[1])
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

    def text(value, maximum=4096):
        if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
            raise ValueError('invalid or oversized source string')
        return value

    def boot_id():
        v = read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if str(uuid.UUID(v)) != v:
            raise ValueError('invalid boot ID')
        return v

    result = {'boot_id':boot_id(), 'source':'Linux procfs/sysfs; installed target utilities', 'unavailable':[]}
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
            values.append({'name':text(p[0],64), 'size_bytes':size, 'references':refs,
                'holders':[text(h,64) for h in holders], 'state':text(p[4],32)})
        return values

    offset = a['offset']
    if type(offset) is not int or not 0 <= offset <= 512:
        raise ValueError('invalid module page offset')
    observed = sorted(modules(), key=lambda row: row['name'])
    result['modules'] = observed[offset:offset + 8]
    result['total_count'] = len(observed)
    result['next_offset'] = offset + 8 if offset + 8 < len(observed) else -1
    result['scope'] = 'name-sorted live procfs pages; concurrent module changes can shift offsets'

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
