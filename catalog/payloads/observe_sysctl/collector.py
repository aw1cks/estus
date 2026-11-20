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

    reviewed={'vm.swappiness':'vm/swappiness','net.ipv4.ip_forward':'net/ipv4/ip_forward','kernel.pid_max':'kernel/pid_max','fs.file-max':'fs/file-max','fs.inotify.max_user_watches':'fs/inotify/max_user_watches','fs.inotify.max_user_instances':'fs/inotify/max_user_instances','kernel.dmesg_restrict':'kernel/dmesg_restrict','kernel.panic':'kernel/panic','kernel.perf_event_paranoid':'kernel/perf_event_paranoid','net.core.somaxconn':'net/core/somaxconn','net.core.netdev_max_backlog':'net/core/netdev_max_backlog','net.core.rmem_max':'net/core/rmem_max','net.core.wmem_max':'net/core/wmem_max','net.ipv4.tcp_syncookies':'net/ipv4/tcp_syncookies','net.ipv4.tcp_max_syn_backlog':'net/ipv4/tcp_max_syn_backlog','net.ipv4.tcp_tw_reuse':'net/ipv4/tcp_tw_reuse','net.ipv4.ip_unprivileged_port_start':'net/ipv4/ip_unprivileged_port_start','vm.overcommit_memory':'vm/overcommit_memory','vm.max_map_count':'vm/max_map_count','vm.dirty_ratio':'vm/dirty_ratio','vm.dirty_background_ratio':'vm/dirty_background_ratio'}
    if not isinstance(args['keys'],list) or not args['keys'] or len(args['keys'])>16 or len(set(args['keys']))!=len(args['keys']): raise ValueError('select one to sixteen unique keys')
    if not isinstance(args['approved_keys'],list) or not args['approved_keys']: raise ValueError('operator approved keys required')
    if '*' in args['approved_keys']:
        effective=set(reviewed)
    else:
        if not set(args['approved_keys']) <= set(reviewed): raise ValueError('operator key outside reviewed safe set')
        effective=set(args['approved_keys'])
    rows=[]
    for key in args['keys']:
        if not isinstance(key,str) or key not in reviewed or key not in effective: raise ValueError('key not operator approved')
        row={'key':key}
        try: value=read('/proc/sys/'+reviewed[key],4096).strip()
        except FileNotFoundError: row['status']='missing'
        except PermissionError: row['status']='denied'
        else:
            if not re.fullmatch(r'[0-9]+',value): raise ValueError('invalid reviewed integer sysctl')
            row.update(status='available',value=number(value))
        rows.append(row)
    emit({'values':rows})



if __name__ == "__main__":
    main()
