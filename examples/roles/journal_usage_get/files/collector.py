def main():
    import os, sys, json, re, time, selectors, subprocess, signal, stat
    MAX=9007199254740991
    args=[json.loads(x) for x in sys.argv[1:]]
    def read(path, bound=65536):
        with open(path,'rb') as f: data=f.read(bound+1)
        if len(data)>bound: raise ValueError('source exceeds bound')
        return data.decode('utf-8',errors='strict').strip()
    def run(argv, bound=1048576):
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SYSTEMD_COLORS':'0'},start_new_session=True)
        streams=selectors.DefaultSelector(); streams.register(p.stdout,selectors.EVENT_READ); streams.register(p.stderr,selectors.EVENT_READ)
        out={p.stdout:bytearray(),p.stderr:bytearray()}; deadline=time.monotonic()+10
        try:
            while streams.get_map():
                if time.monotonic()>deadline: raise ValueError('subprocess deadline')
                for key,_ in streams.select(.1):
                    data=os.read(key.fileobj.fileno(),8192)
                    if not data: streams.unregister(key.fileobj); continue
                    out[key.fileobj].extend(data)
                    if sum(map(len,out.values()))>bound: raise ValueError('subprocess output bound')
            rc=p.wait(timeout=1)
            if rc: raise ValueError('fixed utility failed: '+str(rc)+': '+bytes(out[p.stderr])[:512].decode('utf-8','replace'))
            return bytes(out[p.stdout]).decode('utf-8','strict')
        finally:
            streams.close()
            if p.poll() is None: os.killpg(p.pid,signal.SIGKILL)
            p.wait()
    def publish(value):
        encoded=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>4096: raise ValueError('result bound')
        print(encoded)

    usage=run(['/usr/bin/journalctl','--disk-usage','--no-pager'],4096).strip()
    if len(usage)>1024: raise ValueError('usage bound')
    keys={'SystemMaxUse','SystemKeepFree','SystemMaxFileSize','RuntimeMaxUse','RuntimeKeepFree','RuntimeMaxFileSize','MaxRetentionSec','MaxFileSec','Storage'}
    paths=[]
    for directory in ['/usr/lib','/usr/local/lib','/run','/etc']:
        path=directory+'/systemd/journald.conf'
        if os.path.isfile(path): paths.append(path)
    # Drop-ins override by basename; /etc wins, then /run, then vendor.
    drops={}
    for directory in ['/usr/lib','/usr/local/lib','/run','/etc']:
        folder=directory+'/systemd/journald.conf.d'
        try:
            with os.scandir(folder) as scan:
                for i,e in enumerate(scan):
                    if i>=128: raise ValueError('configuration directory bound')
                    if e.name.endswith('.conf'): drops[e.name]=e.path
        except FileNotFoundError: pass
    paths.extend(drops[k] for k in sorted(drops))
    if len(paths)>132: raise ValueError('configuration file count bound')
    assignments=[]
    for path in paths:
        if len(path)>512: raise ValueError('config path bound')
        section=''
        for line in read(path,32768).splitlines():
            if len(line)>1024: raise ValueError('config line bound')
            line=line.strip()
            if not line or line.startswith(('#',';')): continue
            if line.startswith('[') and line.endswith(']'): section=line[1:-1]; continue
            if section!='Journal' or '=' not in line: continue
            key,value=map(str.strip,line.split('=',1))
            if key in keys:
                if len(value)>256 or len(assignments)>=256: raise ValueError('retention result bound')
                assignments.append({'path':path,'key':key,'value':value})
    publish({'disk_usage_text':usage,'retention_assignments':assignments,'runtime_retention_known':False})


if __name__ == "__main__":
    main()
