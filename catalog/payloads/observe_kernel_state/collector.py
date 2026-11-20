import estus_runtime


def main():
    import datetime, json, platform
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

    def taint():
        value = int(read('/proc/sys/kernel/tainted',128).strip())
        if not 0 <= value <= 9007199254740991:
            raise ValueError('taint exceeds bound')
        return value

    result.update({'taint':taint(),'kernel_release':estus_runtime.check_text(platform.release(),256)})
    for field,path in [('lockdown','/sys/kernel/security/lockdown'),('signature_enforce','/sys/module/module/parameters/sig_enforce'),('modules_disabled','/proc/sys/kernel/modules_disabled')]:
        value = read(path,4096,optional=True)
        if value is None:
            result['unavailable'].append(field)
        else:
            result[field] = estus_runtime.check_text(value.decode('ascii').strip(),4096)

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
