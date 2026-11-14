def main():
    import json, sys
    raw=sys.stdin.read(1048577)
    if len(raw)>1048576: raise ValueError('inventory exceeds bound')
    facts=json.loads(raw)
    result=[]
    for name, versions in sorted(facts.items()):
        for p in versions:
            item={'name':p['name'],'version':p['version'],'architecture':p['arch'],'source':p['source']}
            if item['source']!='apt' or any(not isinstance(v,str) or len(v)> (96 if k=='version' else 64) for k,v in item.items()): raise ValueError('unsupported package fact')
            result.append(item)
    if len(result)>4096: raise ValueError('inventory exceeds bound')
    offset=int(sys.argv[1]); limit=int(sys.argv[2])
    if not 0<=offset<=4096 or not 1<=limit<=16: raise ValueError('invalid page bounds')
    encoded=json.dumps({'backend':'apt','packages':result[offset:offset+limit],'offset':offset,'total':len(result),'truncated':offset+limit<len(result)},separators=(',',':'))
    if len(encoded)>4096: raise ValueError('page exceeds projection bound')
    print(encoded)


if __name__ == '__main__':
    main()
