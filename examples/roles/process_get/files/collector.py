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

    boot=read('/proc/sys/kernel/random/boot_id',128).strip()
    if not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',boot): raise ValueError('invalid boot identity')
    if not re.fullmatch(r'[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',args['boot_id']): raise ValueError('invalid requested boot identity')
    def stat(directory):
        data=read('stat',8192,directory)
        end=data.rfind(') ')
        if end < 0: raise ValueError('invalid process stat')
        fields=data[end+2:].split()
        if len(fields)<22: raise ValueError('short process stat')
        return {'pid':number(data.split(' ',1)[0]),'name':bounded(data[data.index('(')+1:end],256),'state':bounded(fields[0],1),'ppid':number(fields[1]),'start_ticks':number(fields[19]),'user_ticks':number(fields[11]),'system_ticks':number(fields[12]),'virtual_bytes':number(fields[20]),'resident_pages':number(fields[21]),'boot_id':boot}
    def identity(row): return {k:row[k] for k in ('pid','start_ticks','boot_id')}

    directory=None
    result={'status':'gone','requested':{k:args[k] for k in ('pid','boot_id','start_ticks')}}
    try:
        directory=os.open('/proc/'+str(args['pid']),os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        first=stat(directory)
        result['observed_identity']=identity(first)
        if first['boot_id']!=args['boot_id'] or first['start_ticks']!=args['start_ticks']:
            result['status']='identity_mismatch'
        else:
            result['status']='available'

            status=read('status',65536,directory)
            owner=re.search(r'^Uid:\s+([0-9]+)',status,re.M)
            if not owner: raise ValueError('missing process owner')
            first['uid']=number(owner[1])
            cgroups=read('cgroup',32768,directory).splitlines()
            if len(cgroups)>64: raise ValueError('too many cgroup memberships')
            first['cgroups']=[bounded(value,1024) for value in cgroups]
            lines=read('limits',32768,directory).splitlines()
            if len(lines)>64: raise ValueError('too many process limits')
            limits=[]
            for line in lines[1:]:
                match=re.fullmatch(r'(.+?)\s{2,}(\S+)\s+(\S+)(?:\s+(.*?))?\s*',line)
                if not match: raise ValueError('malformed process limit')
                limits.append({'name':bounded(match[1],64),'soft':bounded(match[2],32),'hard':bounded(match[3],32),'units':bounded(match[4] or '',32)})
            first['limits']=limits
            result['process']=first
            result['clock_ticks_per_second']=number(os.sysconf('SC_CLK_TCK'))
            result['page_size_bytes']=number(os.sysconf('SC_PAGE_SIZE'))

            last=stat(directory)
            # A pinned proc directory cannot silently switch to a reused PID. Check again
            # through the live name too, and never publish mixed/disappearing records.
            live=read('/proc/'+str(args['pid'])+'/stat',8192)
            live_start=number(live[live.rfind(') ')+2:].split()[19])
            if last['start_ticks']!=first['start_ticks'] or live_start!=first['start_ticks']:
                result={'status':'raced','requested':result['requested'],'observed_identity':identity(first)}
    except OSError as error:
        if error.errno in (errno.ENOENT,errno.ESRCH): state='gone'
        elif error.errno in (errno.EACCES,errno.EPERM): state='denied'
        else: raise
        result={'status':state,'requested':result['requested']}
    finally:
        if directory is not None: os.close(directory)
    emit(result)



if __name__ == "__main__":
    main()
