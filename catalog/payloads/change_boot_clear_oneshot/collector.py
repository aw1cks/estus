def main():
    import datetime, json, os, platform, resource, uuid
    if platform.system() != 'Linux':
        raise ValueError('requires Linux')
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

    def require_loader():
        if not loader().startswith('systemd-boot '):
            raise ValueError('unsupported backend: actual systemd-boot EFI boot required')

    require_loader()
    ident = ''
    before = efi('LoaderEntryOneShot')
    mutation = run([os.environ['ESTUS_EXEC_BOOTCTL'],'set-oneshot',ident])
    after = efi('LoaderEntryOneShot')
    verified = after is None if ident == '' else after == ident
    result.update({'entry_id':ident, 'selection_variable':'LoaderEntryOneShot', 'previous_selection':before if before is not None else 'unset',
        'observed_selection':after if after is not None else 'unset', 'reboot_requested':False,
        'outcome':'uncertain' if mutation['timed_out'] else ('verified' if verified and mutation['returncode'] == 0 else 'failed'),
        'command_returncode':mutation['returncode'], 'postcondition_verified':verified,
        'persistent':False})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
