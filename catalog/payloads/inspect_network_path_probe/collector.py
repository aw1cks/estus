import estus_runtime
def main():
    import json, os, ipaddress
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    for field in ('destinations',):
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
    text,_=run([os.environ['ESTUS_EXEC_TRACEROUTE'],'-n','-I','-q','1','-m',str(p['max_hops']),'-w','1',dest,'32'],timeout=p['deadline'],accepted=(0,1))
    hops=[]
    for line in text.splitlines():
        cells=line.split()
        if not cells or not cells[0].isdigit(): continue
        ttl=int(cells[0]); addresses=[]
        for token in cells[1:]:
            try: address=str(ipaddress.ip_address(token))
            except ValueError: continue
            if address not in addresses: addresses.append(address)
        hops.append({'ttl':ttl,'addresses':addresses})
    emit({'destination':dest,'hops':hops,'reached':any(dest in h['addresses'] for h in hops),'max_probes':p['max_hops']})


if __name__ == "__main__":
    main()
