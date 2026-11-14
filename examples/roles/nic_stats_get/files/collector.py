def main():
    import json, os, re, sys, datetime
    unavailable=[]
    def read(path,limit=4096):
        try:
            with open(path,'rb') as f: data=f.read(limit+1)
        except OSError: return None
        if len(data)>limit: raise ValueError('source bound')
        return data.decode().strip()
    def entries(path):
        result=[]
        with os.scandir(path) as it:
            for e in it:
                result.append(e.name)
                if len(result)>256: raise ValueError('entry bound')
        return sorted(result)
    def check(v):
        if isinstance(v,bool) or v is None: return
        if isinstance(v,int):
            if not 0<=v<=9007199254740991: raise ValueError('integer bound')
        elif isinstance(v,str):
            if len(v)>4096 or any(ord(c)<32 for c in v): raise ValueError('string bound')
        elif isinstance(v,list):
            if len(v)>256: raise ValueError('entry bound')
            for x in v: check(x)
        elif isinstance(v,dict):
            if len(v)>256: raise ValueError('field bound')
            for k,x in v.items(): check(k);check(x)
        else: raise ValueError('type')
    def publish(data,source):
        result=dict(source=source,observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),unavailable=unavailable,**data)
        check(result)
        result['truncated']=False
        result['omitted_records']=0
        def nodes(v):
            if isinstance(v,dict):return 1+sum(nodes(x) for x in v.values())
            if isinstance(v,list):return 1+sum(nodes(x) for x in v)
            return 1
        while True:
            out=json.dumps(result,separators=(',',':'))
            if len(out.encode())<=4096 and nodes(result)<=256:break
            # Return a whole-record prefix, never trim strings or unknown metadata.
            candidates=[v for k,v in data.items() if isinstance(v,list) and v]
            if not candidates:raise ValueError('selected record exceeds projection budget')
            max(candidates,key=len).pop()
            result['truncated']=True
            result['omitted_records']+=1
        print(out)
    import subprocess, selectors, time
    def run(argv):
        p=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
        sel=selectors.DefaultSelector();data={}
        for f in (p.stdout,p.stderr): sel.register(f,selectors.EVENT_READ);data[f]=bytearray()
        end=time.monotonic()+6
        try:
            while sel.get_map():
                if time.monotonic()>end: raise TimeoutError('command timeout')
                for key,_ in sel.select(.1):
                    chunk=os.read(key.fd,4096)
                    if not chunk: sel.unregister(key.fileobj);continue
                    data[key.fileobj].extend(chunk)
                    if len(data[key.fileobj])>65536: raise ValueError('command output bound')
            rc=p.wait(timeout=max(.1,end-time.monotonic()))
            return rc,bytes(data[p.stdout]).decode(),bytes(data[p.stderr]).decode()
        finally:
            if p.poll() is None:p.kill()
            p.wait();sel.close();p.stdout.close();p.stderr.close()
    interface=sys.argv[1]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',interface):raise ValueError('interface')
    if not os.path.isdir('/sys/class/net/'+interface):raise ValueError('interface absent')
    rc,text,error=run(['/usr/bin/ethtool','-S',interface])
    counters=[]
    if rc==0:
        for line in text.splitlines():
            m=re.fullmatch(r'\s*([A-Za-z0-9_.:-]{1,128}):\s*([0-9]+)\s*',line)
            if m:
                counters.append({'name':m[1],'value':int(m[2])})
                if len(counters)>256:raise ValueError('counter entry bound')
    else:
        if not any(x in (text+error).lower() for x in ('not supported','cannot get','operation not permitted')):raise ValueError('statistics query failed')
        unavailable.append('driver_statistics')
    publish({'interface':interface,'supported':rc==0,'counters':counters},'ethtool -S driver cumulative counters; not rates')


if __name__ == "__main__":
    main()
