import estus_runtime
def main():
    import json, time, ipaddress, socket
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    for field in ('destinations',):
        value = policy.get(field)
        if not (isinstance(value, list) and value):
            raise ValueError('operator policy requires an explicit ' + field + ' allowlist')
        if any(not isinstance(entry, str) for entry in value):
            raise ValueError('operator policy allowlist entries must be strings')
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
    if not estus_runtime.allowed(str(p['destination_port']), [str(v) for v in policy['ports']]): raise ValueError('port outside operator policy')
    start=time.monotonic()
    connected=False
    try:
        with socket.create_connection((dest,p['destination_port']),timeout=p['timeout']): connected=True
    except (TimeoutError,ConnectionRefusedError,OSError): pass
    emit({'destination':dest,'destination_port':p['destination_port'],'connected':connected,'elapsed_ms':int((time.monotonic()-start)*1000),'bytes_sent':0})


if __name__ == "__main__":
    main()
