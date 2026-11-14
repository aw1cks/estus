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
    rc,text,error=run(['/usr/bin/timedatectl','show','--property=NTPSynchronized','--property=NTP','--property=CanNTP','--property=Timezone','--property=LocalRTC'])
    values={}
    if rc==0:
        for line in text.splitlines():
            k,sep,v=line.partition('=')
            if sep and k in ('NTPSynchronized','NTP','CanNTP','Timezone','LocalRTC'):
                if k in values:raise ValueError('duplicate time property')
                values[k]=v
    else:unavailable.append('timedatectl')
    result={'synchronization':{'yes':'synchronized','no':'unsynchronized'}.get(values.get('NTPSynchronized'),'unknown')}
    for key,out in [('NTP','ntp_enabled'),('CanNTP','ntp_capable'),('LocalRTC','local_rtc')]:
        if values.get(key) in ('yes','no'):result[out]=values[key]=='yes'
        else:unavailable.append(out)
    if values.get('Timezone'):result['timezone']=values['Timezone']
    else:unavailable.append('timezone')
    # Query only the manager-owned timesync daemon when available. No network
    # probing or service activation; other daemons remain explicitly unknown.
    trc,ttext,terror=run(['/usr/bin/timedatectl','timesync-status','--no-pager'])
    labels={'Server':'synchronization_source','Offset':'offset','Leap':'leap','Stratum':'stratum','Root distance':'root_distance','Delay':'delay','Jitter':'jitter','Packet count':'packet_count','Frequency':'frequency'}
    if trc==0:
        for line in ttext.splitlines():
            label,sep,value=line.strip().partition(':')
            if sep and label in labels and value.strip():
                key=labels[label]
                if key in result:raise ValueError('duplicate timesync status field')
                result[key]=value.strip()
    for key in labels.values():
        if key not in result:unavailable.append(key)
    unavailable.extend(['offset_seconds','last_sync_failure'])
    publish({'status':result},'systemd timedatectl manager report, not independent clock accuracy')


if __name__ == "__main__":
    main()
