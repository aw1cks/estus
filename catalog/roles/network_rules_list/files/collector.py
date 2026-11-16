def main():
    import json, sys, subprocess, selectors, time, os
    p = {k:v for k,v in json.loads(sys.argv[1]).items() if v is not None}
    policy = json.loads(sys.argv[2])
    SCOPE = 'current_network_namespace'
    def run(argv, timeout=5, accepted=(0,)):
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        sel.register(proc.stderr, selectors.EVENT_READ)
        data = {proc.stdout: bytearray(), proc.stderr: bytearray()}
        end = time.monotonic() + timeout
        try:
            while sel.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0: raise ValueError('network command deadline exceeded')
                for key, _ in sel.select(min(remaining, .2)):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk: sel.unregister(key.fileobj); continue
                    data[key.fileobj].extend(chunk)
                    if len(data[key.fileobj]) > 131072: raise ValueError('network command output bound exceeded')
            rc = proc.wait(timeout=max(.01, end-time.monotonic()))
            if rc not in accepted: raise ValueError('network command failed: '+bytes(data[proc.stderr])[:1024].decode('utf8','replace'))
            return bytes(data[proc.stdout]).decode('utf8'), rc
        finally:
            sel.close()
            if proc.poll() is None: proc.kill()
            proc.wait()
    def ip(args):
        rows = json.loads(run(['/usr/bin/ip','-j']+args)[0])
        if not isinstance(rows,list) or len(rows)>512: raise ValueError('network inventory entry bound exceeded')
        return rows
    def emit(value):
        if 'entries' in value:
            entries=value['entries']
            maximum=p.get('limit',16)
            value['entries']=entries[:maximum]
            value['truncated']=len(entries)>maximum
            value.setdefault('scope',SCOPE)
        def measure(v,depth=0):
            if depth>8: raise ValueError('result depth exceeded')
            if isinstance(v,str) and len(v)>512: raise ValueError('result string exceeded')
            if isinstance(v,int) and not isinstance(v,bool) and not 0<=v<=9007199254740991: raise ValueError('result integer exceeded')
            if isinstance(v,dict):
                if len(v)>32: raise ValueError('result object exceeded')
                return 1+sum(measure(x,depth+1) for x in v.values())
            if isinstance(v,list):
                if len(v)>128: raise ValueError('result entries exceeded')
                return 1+sum(measure(x,depth+1) for x in v)
            return 1
        while True:
            nodes=measure(value)
            raw=json.dumps(value,separators=(',',':'),allow_nan=False,ensure_ascii=True)
            if nodes<=256 and len(raw.encode('ascii'))<=4096: break
            if 'entries' not in value or not value['entries']: raise ValueError('result exceeds projection budget')
            value['entries'].pop()
            value['truncated']=True
        print(raw)

    rows=ip(['-6' if p.get('family')=='inet6' else '-4','rule','show'])
    out=[]
    for r in rows:
        x={}
        for src,dst in [('priority','priority'),('src','source'),('dst','destination'),('table','table'),('action','action')]:
            if src in r: x[dst]=r[src] if dst=='priority' else str(r[src])
        out.append(x)
    emit({'entries':out})


if __name__ == "__main__":
    main()
