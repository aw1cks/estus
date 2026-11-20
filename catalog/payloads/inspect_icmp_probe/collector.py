import estus_runtime
def main():
    import json, os, ipaddress, re
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    for field in ('destinations'):
        value = policy.get(field)
        if not (isinstance(value, list) and value):
            raise ValueError('operator policy requires an explicit ' + field + ' allowlist')
        if any(not isinstance(entry, str) for entry in value):
            raise ValueError('operator policy allowlist entries must be strings')
    def run(argv, timeout=5, accepted=(0,)):
        result = estus_runtime.run_bounded(
            argv, timeout=timeout, max_bytes=131072, accepted=accepted)
        return result['stdout'], result['returncode']
    def destination():
        value=str(ipaddress.ip_address(p['destination']))
        if not estus_runtime.allowed(value, policy['destinations']): raise ValueError('destination outside operator policy')
        return value
    def emit(value):
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
            raise ValueError('result exceeds projection budget')
        print(raw)

    dest=destination()
    text,rc=run([os.environ['ESTUS_EXEC_PING'],'-n','-c',str(p['count']),'-w',str(p['deadline']),'-s','16',dest],timeout=p['deadline']+1,accepted=(0,1))
    m=re.search(r'(\d+) packets transmitted, (\d+) (?:packets )?received',text)
    if m is None: raise ValueError('unsupported ping statistics')
    sent,received=map(int,m.groups())
    emit({'destination':dest,'transmitted':sent,'received':received,'payload_bytes':16,'reachable':received>0})


if __name__ == "__main__":
    main()
