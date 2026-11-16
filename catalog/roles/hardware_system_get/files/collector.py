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
    raw=sys.stdin.buffer.read(98305)
    if len(raw)>98304:raise ValueError('fact input bound')
    facts=json.loads(raw)
    values={}
    for key in ['system_vendor', 'product_name', 'product_version', 'board_vendor', 'board_name', 'board_version', 'bios_vendor', 'bios_version', 'bios_date']:
        value=facts.get('ansible_'+key)
        if value is None or str(value).strip().lower() in ('','na','none','unknown','not specified','not available','default string'):unavailable.append(key)
        else:values[key]=value
    publish({'values':values},'ansible.builtin.setup hardware DMI')


if __name__ == "__main__":
    main()
