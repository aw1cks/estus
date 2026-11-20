import estus_runtime
def main():
    import json, os, re
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
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
        if (policy['interfaces'] and '*' not in policy['interfaces'] and (not value or value not in policy['interfaces'])) or not re.fullmatch('[a-zA-Z0-9_.-]{1,15}',value or ''): raise ValueError('interface outside operator policy')
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
    rows=ip(['-s','link','show','dev',dev])
    r=rows[0]; stats=r.get('stats64',r.get('stats'))
    if stats is None: raise ValueError('interface statistics unavailable')
    out={}
    for direction in ['rx','tx']:
        for key in ['bytes','packets','errors','dropped']: out[direction+'_'+key]=stats[direction][key]
    emit({'interface':dev,'counters':out})


if __name__ == "__main__":
    main()
