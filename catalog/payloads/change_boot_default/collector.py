import estus_runtime
def main():
    import datetime, json, os, re, platform, resource, uuid
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
    LOADER_GUID = '4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
    def efi(name, guid=LOADER_GUID, binary=False):
        b = read('/sys/firmware/efi/efivars/' + name + '-' + guid, 8192, optional=True)
        if b is None:
            return None
        if len(b) < 4:
            raise ValueError('malformed EFI variable')
        return b[4:] if binary else text(b[4:].decode('utf-16-le').rstrip('\x00'), 2048)

    def loader():
        value = efi('LoaderInfo')
        return value if value is not None else 'unknown'

    def entries():
        data = json.loads(checked([os.environ['ESTUS_EXEC_BOOTCTL'], '--json=short', '--no-pager', 'list']))
        if not isinstance(data, list) or len(data) > 128:
            raise ValueError('boot entry count exceeds bound')
        selected = []
        ids = set()
        for e in data:
            ident = text(e.get('id'), 255)
            if not ident or ident in ids:
                raise ValueError('missing or duplicate exact entry ID')
            ids.add(ident)
            v = {'entry_id':ident, 'source':text(e.get('source', 'unknown'), 128),
                 'type':text(e.get('type', 'unknown'), 128), 'command_line_sensitive':True,
                 'unknown':[]}
            for key, alias in [('linux','linux'), ('efi','efi'), ('title','title'), ('path','path')]:
                if key in e:
                    v[alias] = text(e[key], 2048)
                else:
                    v['unknown'].append(alias)
            if 'initrd' in e:
                if not isinstance(e['initrd'], list) or len(e['initrd']) > 16:
                    raise ValueError('initrd list exceeds bound')
                v['initrd'] = [text(i, 2048) for i in e['initrd']]
            else:
                v['unknown'].append('initrd')
            selected.append((v, e))
        return selected

    def require_loader():
        if not loader().startswith('systemd-boot '):
            raise ValueError('unsupported backend: actual systemd-boot EFI boot required')

    def selected_entry():
        ident = a['entry_id']
        if not isinstance(ident, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_@.+:-]{0,254}', ident) or '..' in ident:
            raise ValueError('entry ID invalid')
        allowed = a.get('allowed_entries')
        if not estus_runtime.allowed(ident, allowed):
            raise ValueError('entry ID not approved')
        matches = [(v,e) for v,e in entries() if v['entry_id'] == ident]
        if len(matches) != 1:
            raise ValueError('approved exact entry is not installed')
        return matches[0]
    require_loader()
    v,e = selected_entry()
    ident = v['entry_id']
    before = efi('LoaderEntryDefault')
    mutation = run([os.environ['ESTUS_EXEC_BOOTCTL'],'set-default','--',ident])
    after = efi('LoaderEntryDefault')
    verified = after == ident
    result.update({'entry_id':ident, 'selection_variable':'LoaderEntryDefault', 'previous_selection':before if before is not None else 'unset',
        'observed_selection':after if after is not None else 'unset', 'reboot_requested':False,
        'outcome':'uncertain' if mutation['timed_out'] else ('verified' if verified and mutation['returncode'] == 0 else 'failed'),
        'command_returncode':mutation['returncode'], 'postcondition_verified':verified,
        'persistent':True})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
