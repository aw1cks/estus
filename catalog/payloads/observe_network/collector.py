import estus_runtime
def main():
    import json, os, re
    ASPECTS = ('links', 'addresses', 'neighbors', 'stats')
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    for field in ('interfaces'):
        value = policy.get(field)
        if not (isinstance(value, list) and value):
            raise ValueError('operator policy requires an explicit ' + field + ' allowlist')
        if any(not isinstance(entry, str) for entry in value):
            raise ValueError('operator policy allowlist entries must be strings')
    SCOPE = 'approved_interfaces'
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
    def publish(value):
        while True:
            nodes=measure(value)
            raw=json.dumps(value,separators=(',',':'),allow_nan=False,ensure_ascii=True)
            if nodes<=256 and len(raw.encode('ascii'))<=4096: break
            block=value.get('links') or value.get('addresses') or value.get('neighbors')
            if block is None or not block['entries']: raise ValueError('result exceeds projection budget')
            block['entries'].pop()
            block['truncated']=True
        print(raw)
    def listed(entries):
        maximum=p.get('limit',16)
        return {'entries':entries[:maximum],'truncated':len(entries)>maximum,'scope':SCOPE}

    aspect=p.get('aspect')
    if aspect not in ASPECTS: raise ValueError('unsupported network aspect')
    result={'aspect':aspect}
    if aspect=='links':
        args=['-d','link','show']
        if 'interface' in p: args+=['dev',interface()]
        out=[]
        for r in ip(args):
            if not estus_runtime.allowed(r['ifname'], policy['interfaces']): continue
            x={'interface':r['ifname'],'index':r['ifindex'],'mtu':r['mtu'],'state':r['operstate'],'flags':r.get('flags',[])}
            for k in ['address','master']:
                if k in r: x[k]=str(r[k])
            if 'info_kind' in r.get('linkinfo',{}): x['kind']=r['linkinfo']['info_kind']
            out.append(x)
        result['links']=listed(out)
    elif aspect=='addresses':
        args=['address','show']
        if 'interface' in p: args+=['dev',interface()]
        out=[]
        for r in ip(args):
            if not estus_runtime.allowed(r['ifname'], policy['interfaces']): continue
            for a in r.get('addr_info',[]):
                if p.get('family',a['family'])!=a['family'] or p.get('scope',a['scope'])!=a['scope']: continue
                out.append({'interface':r['ifname'],'family':a['family'],'address':a['local'],'prefix_length':a['prefixlen'],'scope':a['scope']})
        result['addresses']=listed(out)
    elif aspect=='neighbors':
        args=['-6' if p.get('family')=='inet6' else '-4','neighbor','show']
        selected=interface() if 'interface' in p else None
        if selected is not None: args+=['dev',selected]
        out=[]
        for r in ip(args):
            dev=selected if selected is not None else r['dev']
            if not estus_runtime.allowed(dev, policy['interfaces']): continue
            x={'destination':r['dst'],'interface':dev,'state':r.get('state',[])}
            if 'lladdr' in r: x['address']=r['lladdr']
            out.append(x)
        result['neighbors']=listed(out)
    else:
        # Counters describe one interface, so it cannot be defaulted from policy.
        if 'interface' not in p: raise ValueError('interface is required for the stats aspect')
        dev=interface()
        r=ip(['-s','link','show','dev',dev])[0]
        stats=r.get('stats64',r.get('stats'))
        if stats is None: raise ValueError('interface statistics unavailable')
        counters={}
        for direction in ['rx','tx']:
            for key in ['bytes','packets','errors','dropped']: counters[direction+'_'+key]=stats[direction][key]
        result['stats']={'interface':dev,'counters':counters}
    publish(result)


if __name__ == "__main__":
    main()
