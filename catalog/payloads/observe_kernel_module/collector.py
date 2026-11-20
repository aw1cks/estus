import estus_runtime
def main():
    import datetime, json, os, platform, re, resource, uuid
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

    def text(value, maximum=4096):
        if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
            raise ValueError('invalid or oversized source string')
        return value

    def boot_id():
        v = read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if str(uuid.UUID(v)) != v:
            raise ValueError('invalid boot ID')
        return v

    def child_limits():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_FSIZE, (262144, 262144))

    def run(argv):
        return estus_runtime.run_bounded(
            argv, timeout=12, max_bytes=262144, accepted=None,
            env={'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'})

    def checked(argv):
        return run(argv)['stdout']

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

    def approved():
        name = a['name']
        if name not in ('dummy', 'estus_catalog'):
            raise ValueError('module name not approved')
        return name

    def metadata(name):
        raw = checked([os.environ['ESTUS_EXEC_MODINFO'], '-0', name])
        values = {}
        records = raw.split('\x00')
        if len(records) > 512:
            raise ValueError('module metadata exceeds record bound')
        for row in records:
            if not row.strip():
                continue
            # kmod NUL records use key=value; older versions used key: value.
            separator = '=' if re.match(r'^[A-Za-z_][A-Za-z0-9_]*=', row) else ':'
            k, sep, v = row.partition(separator)
            if not sep:
                raise ValueError('malformed module metadata')
            k, v = k.strip(), text(v.strip(),4096)
            if k in ('filename','name','license','description','depends','softdep','vermagic','signer','sig_key','sig_hashalgo','parm','parmtype'):
                values.setdefault(k, []).append(v)
        # Signature is metadata only; kernel policy, keys, hooks and current state still decide loadability.
        return values

    name = approved()
    result.update({'name':name,'metadata':metadata(name),'loaded':any(v['name'] == name for v in modules()),'signer_is_trust_proof':False})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
