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

    key,value=args[0],args[1]
    approved_keys=args[2] if len(args)>=3 else ['kernel.printk_ratelimit']
    if (not isinstance(approved_keys,list) or not isinstance(key,str) or key not in approved_keys
            or '..' in key or '/' in key or not re.fullmatch(r'[a-z0-9_]+(?:\.[a-z0-9_-]+)+',key)
            or type(value) is not int or not 0<=value<=MAX):
        raise ValueError('unapproved typed sysctl')
    if key=='kernel.printk_ratelimit' and not 0<=value<=60:
        raise ValueError('unapproved typed sysctl')
    proc='/proc/sys/'+key.replace('.','/')
    def current():
        text=read(proc,64)
        if not re.fullmatch('[0-9]{1,16}',text): raise ValueError('invalid sysctl readback')
        return int(text)
    before=current()

    run([os.environ['ESTUS_EXEC_SYSCTL'],'--write',key+'='+str(value)],4096)

    after=current()
    if after!=value: raise ValueError('runtime readback mismatch; operation may already have effects')
    publish({'key':key,'before':before,'value':after,'verified':True,'persistent':False,'application':'single_key_sysctl_write','config_path':'','atomic_compare_exchange':False,'rollback_guaranteed':False})


if __name__ == "__main__":
    main()
