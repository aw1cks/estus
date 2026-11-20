import estus_runtime


def main():
    import datetime, json, os, platform
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

    result = {'boot_id':estus_runtime.boot_id(), 'source':'Linux procfs/sysfs; installed target utilities', 'unavailable':[]}
    LOADER_GUID = '4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'
    def efi(name, guid=LOADER_GUID, binary=False):
        b = read('/sys/firmware/efi/efivars/' + name + '-' + guid, 8192, optional=True)
        if b is None:
            return None
        if len(b) < 4:
            raise ValueError('malformed EFI variable')
        return b[4:] if binary else estus_runtime.check_text(b[4:].decode('utf-16-le').rstrip('\x00'), 2048)

    def loader():
        value = efi('LoaderInfo')
        return value if value is not None else 'unknown'

    result.update({'firmware_mode':'efi' if os.path.isdir('/sys/firmware/efi') else 'bios', 'loader':loader(),
                   'selection_source':'EFI Boot Loader Interface variables', 'security_source':'UEFI global variables'})
    for field, variable in [('current_entry','LoaderEntrySelected'),('default_entry','LoaderEntryDefault'),('oneshot_entry','LoaderEntryOneShot')]:
        v = efi(variable)
        if v is None:
            result['unavailable'].append(field)
        else:
            result[field] = v
    for field, variable in [('secure_boot','SecureBoot'),('setup_mode','SetupMode')]:
        b = efi(variable,'8be4df61-93ca-11d2-aa0d-00e098032b8c',True)
        result[field] = 'unknown' if b is None else ('enabled' if b == b'\x01' else 'disabled' if b == b'\x00' else 'unknown')

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
