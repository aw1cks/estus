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

    limit=args[0]
    text=run(['/usr/bin/journalctl','--list-boots','--no-pager','--quiet'],262144)
    lines=text.splitlines()
    if len(lines)>2048: raise ValueError('boot source count bound')
    boots=[]
    for line in lines:
        if re.fullmatch(r'\s*IDX\s+BOOT ID\s+FIRST ENTRY\s+LAST ENTRY\s*',line): continue
        match=re.fullmatch(r'\s*(-?[0-9]{1,10})\s+([0-9a-f]{32})\s+(.{1,256})',line)
        if not match: raise ValueError('unexpected boot listing')
        index=int(match[1])
        if not -2147483648<=index<=2147483647: raise ValueError('boot index bound')
        boots.append({'index':index,'boot_id':match[2],'retained_range_text':match[3]})
    publish({'boots':boots[-limit:],'truncated':len(boots)>limit,'incomplete':True})


if __name__ == "__main__":
    main()
