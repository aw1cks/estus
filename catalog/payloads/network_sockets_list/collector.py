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

    proto=p.get('protocol','tcp')
    args=['/usr/bin/ss','-H','-n','-O','-a','-t' if proto=='tcp' else '-u']
    text,_=run(args)
    out=[]
    for line in text.splitlines():
        if len(line)>2048: raise ValueError('socket line bound exceeded')
        cells=line.split()
        if len(cells)!=5: raise ValueError('unexpected socket inspection format')
        state,rq,sq,local,peer=cells
        la,lp=local.rsplit(':',1); pa,pp=peer.rsplit(':',1)
        la=la.strip('[]'); pa=pa.strip('[]')
        if p.get('state')=='listening' and state not in ('LISTEN','UNCONN'): continue
        if p.get('state')=='established' and state!='ESTAB': continue
        if 'address' in p and la!=p['address']: continue
        if 'local_port' in p and lp!=str(p['local_port']): continue
        out.append({'protocol':proto,'state':state,'local_address':la,'local_port':0 if lp=='*' else int(lp),'peer_address':pa,'peer_port':0 if pp=='*' else int(pp),'receive_queue':int(rq),'send_queue':int(sq)})
    emit({'entries':out,'process_attribution':'not_collected'})


if __name__ == "__main__":
    main()
