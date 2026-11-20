import estus_runtime
def main():
    import json, os, ipaddress, re
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    for field in ('interfaces', 'routes'):
        value = policy.get(field)
        if not (isinstance(value, list) and value):
            raise ValueError('operator policy requires an explicit ' + field + ' allowlist')
        if any(not isinstance(entry, str) for entry in value):
            raise ValueError('operator policy allowlist entries must be strings')
    def run(argv, timeout=5, accepted=(0,)):
        result = estus_runtime.run_bounded(
            argv, timeout=timeout, max_bytes=131072, accepted=accepted)
        return result['stdout'], result['returncode']
    def ip(args):
        rows = json.loads(run([os.environ['ESTUS_EXEC_IP'],'-j']+args)[0])
        if not isinstance(rows,list) or len(rows)>512: raise ValueError('network inventory entry bound exceeded')
        return rows
    def interface():
        value=p.get('interface',policy.get('interface'))
        if not estus_runtime.allowed(value, policy['interfaces']) or not re.fullmatch('[a-zA-Z0-9_.-]{1,15}',value or ''): raise ValueError('interface outside operator policy')
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

    dev=interface()
    net=str(ipaddress.ip_network(p['destination']))
    if (not estus_runtime.allowed(dev, policy['interfaces'])) or (not estus_runtime.allowed(net, policy['routes'])): raise ValueError('route mutation outside policy')
    run([os.environ['ESTUS_EXEC_IP'],'route','add',net,'dev',dev,'table','254'])
    found=any(r.get('dst')==net and r.get('dev')==dev for r in ip(['route','show','table','254','exact',net]))
    if found!=True: raise ValueError('route readback mismatch')
    emit({'interface':dev,'operation':'network_route_add','verified':True,'persistence':'runtime_only'})


if __name__ == "__main__":
    main()
