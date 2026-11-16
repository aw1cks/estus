def main():
    import datetime, json, os, platform, stat, sys, uuid
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
                    'value':text(data.decode('utf-8').strip(),4096),'source':'sysfs'})
        return values

    name = approved()
    parameter = a['parameter']
    value = a['value']
    if parameter != 'value' or name != 'estus_catalog' or type(value) is not int or not 0 <= value <= 1024:
        raise ValueError('module/parameter/value combination not approved')
    observation = parameter_values(name)[0]
    result.update({'name':name,'parameter':parameter,'requested_value':value,'quiescence_proven':False})
    result['mutation_attempted'] = False
    if not observation['supported'] or not observation['writable']:
        result.update({'outcome':'unsupported','postcondition_verified':False})
    else:
        path = '/sys/module/' + name + '/parameters/value'
        result['previous_value'] = observation['value']
        try:
            with open(path,'w',encoding='ascii') as f:
                result['mutation_attempted'] = True
                f.write(str(value) + '\n')
            after = read(path,4096).decode('ascii').strip()
            result.update({'observed_value':after,'postcondition_verified':after == str(value),
                'outcome':'verified' if after == str(value) else 'failed'})
        except OSError:
            result.update({'outcome':'uncertain','postcondition_verified':False})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
