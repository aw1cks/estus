import estus_runtime
def main():
    import datetime, json, os, platform, stat
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

    def approved():
        name = a['name']
        if name not in ('dummy', 'estus_catalog'):
            raise ValueError('module name not approved')
        return name

    def parameter_values(name):
        allowed = ['numdummies'] if name == 'dummy' else ['value']
        values = []
        for parameter in allowed:
            path = '/sys/module/' + name + '/parameters/' + parameter
            data = read(path, 4096, optional=True)
            if data is None:
                values.append({'parameter':parameter,'supported':False,'writable':False,'source':'sysfs'})
            else:
                mode = os.stat(path).st_mode
                values.append({'parameter':parameter,'supported':True,'writable':bool(mode & stat.S_IWUSR),
                    'value':estus_runtime.check_text(data.decode('utf-8').strip(),4096),'source':'sysfs'})
        return values

    name = approved()
    result.update({'name':name,'parameters':parameter_values(name),'approval_scope':'only operator-reviewed parameter names; absent or unreadable values are unsupported'})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
