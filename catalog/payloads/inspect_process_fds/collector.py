import estus_runtime
def main():
    import os, json, re, signal, platform, datetime, errno
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('observation deadline')))
    signal.alarm(12)
    if platform.system() != 'Linux':
        raise ValueError('Linux required')
    args = estus_runtime.request()[0]
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

            descriptors=[]; truncated=False
            with os.scandir('/proc/'+str(args['pid'])+'/fd') as entries:
                for index,entry in enumerate(entries):
                    if index>=4096: truncated=True; break
                    if not entry.name.isdecimal(): continue
                    if len(descriptors)==args['limit']: truncated=True; break
                    try:
                        target=os.readlink('fd/'+entry.name,dir_fd=directory)
                        descriptors.append({'fd':number(entry.name),'status':'available','target':bounded(target,4096)})
                    except FileNotFoundError:
                        descriptors.append({'fd':number(entry.name),'status':'gone'})
                    except PermissionError:
                        descriptors.append({'fd':number(entry.name),'status':'denied'})
            result['descriptors']=descriptors
            result['truncated']=truncated

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
