import estus_runtime
def main():
    import json, os, re, datetime
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
    def run(argv):
        result = estus_runtime.run_bounded(
            argv, timeout=6, max_bytes=65536, accepted=None)
        return result['returncode'], result['stdout'], result['stderr']
    interface=estus_runtime.request()[0]
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',interface):raise ValueError('interface')
    if not os.path.isdir('/sys/class/net/'+interface):raise ValueError('interface absent')
    rc,text,error=run([os.environ['ESTUS_EXEC_ETHTOOL'], '-c']+[interface])
    keys=['rx_usecs', 'rx_frames', 'rx_usecs_irq', 'rx_frames_irq', 'tx_usecs', 'tx_frames', 'tx_usecs_irq', 'tx_frames_irq', 'stats_block_usecs', 'pkt_rate_low', 'rx_usecs_low', 'rx_frames_low', 'tx_usecs_low', 'tx_frames_low', 'pkt_rate_high', 'rx_usecs_high', 'rx_frames_high', 'tx_usecs_high', 'tx_frames_high', 'sample_interval']
    values={}
    section=''
    if rc==0:
        for line in text.splitlines():
            line=line.strip()
            if line in ('Pre-set maximums:','Current hardware settings:'):
                section='maximum_' if line.startswith('Pre-set') else 'current_'
                continue
            label,sep,value=line.partition(':')
            key=section+label.lower().replace(' ','_').replace('-','_')
            if sep and key in keys:
                if key in values:raise ValueError('duplicate selected field')
                values[key]=value.strip()
    else:
        if not any(x in (text+error).lower() for x in ('not supported','unsupported','cannot get','operation not permitted')):raise ValueError('ethtool query failed')
    for key in keys:
        if key not in values:unavailable.append(key)
    publish({'interface':interface,'supported':rc==0,'values':values},'ethtool fixed read-only driver query; non-atomic')


if __name__ == "__main__":
    main()
