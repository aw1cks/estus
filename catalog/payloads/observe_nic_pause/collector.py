def main():
    import json, os, re, selectors, subprocess, sys, time
    p=json.loads(sys.argv[1]); policy=json.loads(sys.argv[2])
    def run(args):
        proc=subprocess.Popen([os.environ['ESTUS_EXEC_ETHTOOL']]+args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'LC_ALL':'C','PATH':'/usr/bin:/bin'})
        sel=selectors.DefaultSelector(); data={}
        for stream in (proc.stdout,proc.stderr): sel.register(stream,selectors.EVENT_READ); data[stream]=bytearray()
        end=time.monotonic()+6
        try:
            while sel.get_map():
                if time.monotonic()>=end: raise ValueError('ethtool deadline exceeded; mutation may have applied')
                for key,_ in sel.select(.1):
                    chunk=os.read(key.fd,4096)
                    if not chunk: sel.unregister(key.fileobj); continue
                    data[key.fileobj].extend(chunk)
                    if len(data[key.fileobj])>65536: raise ValueError('ethtool output exceeded bound; mutation may have applied')
            rc=proc.wait(timeout=max(.01,end-time.monotonic()))
            if rc: raise ValueError('ethtool failed; mutation may have applied: '+bytes(data[proc.stderr])[:1024].decode('utf8','replace'))
            return bytes(data[proc.stdout]).decode('utf8')
        finally:
            sel.close()
            if proc.poll() is None: proc.kill()
            proc.wait(); proc.stdout.close(); proc.stderr.close()
    dev=p['interface']
    if dev!=policy['interface'] or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',dev): raise ValueError('interface outside operator policy')
    with open('/sys/class/net/'+dev+'/address') as f: mac=f.read(64).strip()
    if mac!=policy['mac']: raise ValueError('interface identity mismatch')
    identity=run(['-i',dev])
    if not re.search(r'^driver: '+re.escape(policy['driver'])+r'$',identity,re.M): raise ValueError('driver outside reviewed policy')
    def selected(flag, labels, section=None):
        values={}; active=section is None
        for line in run([flag,dev]).splitlines():
            line=line.strip()
            if section and line.endswith(':') and line in ('Pre-set maximums:','Current hardware settings:'): active=line==section
            label,sep,value=line.partition(':')
            if active and sep and label in labels:
                if label in values: raise ValueError('duplicate selected field')
                values[label]=value.strip()
        if set(values)!=set(labels): raise ValueError('selected driver capability unavailable')
        return values
    def number(value):
        if not re.fullmatch(r'[0-9]{1,7}',value): raise ValueError('invalid numeric driver field')
        n=int(value)
        if n>1048576: raise ValueError('numeric driver field exceeds bound')
        return n
    def switch(value):
        if value not in ('on','off'): raise ValueError('invalid boolean driver field')
        return value=='on'
    def emit(value):
        raw=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(raw.encode())>4096: raise ValueError('projection bound exceeded')
        print(raw)
    v=selected('-a',['Autonegotiate','RX','TX'])
    emit({'interface':dev,'autoneg':switch(v['Autonegotiate']),'rx':switch(v['RX']),'tx':switch(v['TX']),'source':'ethtool -a; driver-reported flow control, not wire-level proof'})


if __name__ == "__main__":
    main()
