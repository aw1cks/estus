import estus_runtime
def main():
    import json, os, ipaddress
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    interfaces = policy.get('interfaces')
    if not (isinstance(interfaces, list) and interfaces) or any(not isinstance(entry, str) for entry in interfaces):
        raise ValueError('operator policy requires an explicit interfaces allowlist')
    SCOPE = 'current_network_namespace'
    def run(argv, timeout=5, accepted=(0,)):
        result = estus_runtime.run_bounded(
            argv, timeout=timeout, max_bytes=131072, accepted=accepted)
        return result['stdout'], result['returncode']
    def ip(args):
        rows = json.loads(run([os.environ['ESTUS_EXEC_IP'],'-j']+args)[0])
        if not isinstance(rows,list) or len(rows)>512: raise ValueError('network inventory entry bound exceeded')
        return rows
    def emit(value):
        if 'entries' in value:
            entries=value['entries']
            maximum=p.get('limit',16)
            value['entries']=entries[:maximum]
            value['truncated']=len(entries)>maximum
            value.setdefault('scope',SCOPE)
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
            if 'entries' not in value or not value['entries']: raise ValueError('result exceeds projection budget')
            value['entries'].pop()
            value['truncated']=True
        print(raw)

    def routes(rows):
        out=[]
        for r in rows:
            # Routes bound to an unapproved interface are omitted; routes with
            # no device (blackhole, unreachable) apply to every interface.
            if 'dev' in r and not estus_runtime.allowed(r['dev'], interfaces): continue
            x={}
            for src,dst in [('dst','destination'),('dev','interface'),('gateway','gateway'),('prefsrc','source'),('table','table'),('protocol','protocol'),('scope','scope'),('type','type'),('metric','metric')]:
                if src in r: x[dst]=r[src] if dst=='metric' else str(r[src])
            out.append(x)
        return out
    args=['-6' if p.get('family')=='inet6' else '-4','route','show','table',str(p.get('table',254))]
    if 'destination' in p: args+=['exact',str(ipaddress.ip_network(p['destination']))]
    emit({'entries':routes(ip(args))})


if __name__ == "__main__":
    main()
