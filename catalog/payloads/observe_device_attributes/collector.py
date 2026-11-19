def main():
    import os, sys, json, re, time, signal, platform, datetime, errno
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('observation deadline')))
    signal.alarm(12)
    if platform.system() != 'Linux':
        raise ValueError('Linux required')
    args = json.loads(sys.argv[1])
    MAX = 9007199254740991
    def number(value):
        value = int(value)
        if not 0 <= value <= MAX: raise ValueError('integer outside projection bound')
        return value
    def read(path, bound=65536, directory=None):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream: data = stream.read(bound + 1)
        if len(data) > bound: raise ValueError('source exceeds read bound')
        return data.decode('utf-8', 'strict')
    def bounded(value, maximum=256):
        if len(value) > maximum: raise ValueError('string exceeds projection bound')
        return value
    def emit(value):
        value['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')
        data = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(data.encode()) > 4096: raise ValueError('output exceeds bound')
        print(data)

    classes={'net':{'mtu','operstate','address'},'block':{'size','ro','removable'}}
    if not 1<=len(args['reviewed_devices'])<=32: raise ValueError('too many configured devices')
    for alias,spec in args['reviewed_devices'].items():
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,32}',alias): raise ValueError('invalid device alias')
        if set(spec)!={'class','name','attributes'} or spec['class'] not in classes: raise ValueError('unreviewed class')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,64}',spec['name']) or spec['name'] in ('.','..'): raise ValueError('invalid device name')
        if not set(spec['attributes']) <= classes[spec['class']]: raise ValueError('unreviewed attribute')
    spec=args['reviewed_devices'][args['device']]
    if not args['attributes'] or len(set(args['attributes']))!=len(args['attributes']): raise ValueError('unique attributes required')
    if not set(args['attributes']) <= set(spec['attributes']): raise ValueError('attribute not operator approved')
    path=os.path.realpath('/sys/class/'+spec['class']+'/'+spec['name'])
    if not path.startswith('/sys/devices/'): raise ValueError('device outside sysfs devices')
    rows=[]
    for attribute in args['attributes']:
        row={'attribute':attribute}
        try:
            resolved=os.path.realpath(path+'/'+attribute)
            if not resolved.startswith(path+'/'): raise ValueError('attribute escapes device')
            value=bounded(read(resolved,4096).rstrip('\n'),4096)
        except FileNotFoundError: row['status']='missing'
        except PermissionError: row['status']='denied'
        else: row.update(status='available',value=value)
        rows.append(row)
    emit({'device':args['device'],'class':spec['class'],'name':spec['name'],'sysfs_path':bounded(path,1024),'attributes':rows})



if __name__ == "__main__":
    main()
