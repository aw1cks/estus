import estus_runtime
def main():
    import json, os, re, datetime
    ASPECTS=('identity','driver','iommu')
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
            if not candidates:
                raise ValueError('selected record exceeds projection budget')
            max(candidates,key=len).pop()
            result['truncated']=True
            result['omitted_records']+=1
        print(out)
    root='/sys/bus/pci/devices'
    pattern=r'[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]'
    def device(address):
        if not re.fullmatch(pattern,address) or not os.path.isdir(root+'/'+address):raise ValueError('PCI address absent or invalid')
        result={'address':address}
        for k in ('vendor','device','class','subsystem_vendor','subsystem_device','revision'):
            v=read(root+'/'+address+'/'+k,32)
            if v is None:unavailable.append(address+'.'+k)
            elif re.fullmatch(r'0x[0-9a-fA-F]{2,8}',v):result[k]=v.lower()
            else:raise ValueError('PCI numeric identity malformed')
        return result
    request=estus_runtime.request()[0]
    address=request.get('address')
    aspect=request.get('aspect')
    if aspect not in ASPECTS:raise ValueError('unsupported PCI aspect')
    identity=device(address)
    path=root+'/'+address
    result={'address':address,'aspect':aspect}
    if aspect=='identity':
        result['identity']=identity
        source='Linux PCI sysfs numeric identity'
    elif aspect=='driver':
        binding={'address':address,'bound':os.path.islink(path+'/driver')}
        if binding['bound']:
            binding['driver']=os.path.basename(os.path.realpath(path+'/driver'))
            if os.path.islink(path+'/driver/module'):binding['module']=os.path.basename(os.path.realpath(path+'/driver/module'))
            else:unavailable.append('module')
        else:unavailable.extend(['driver','module'])
        result['binding']=binding
        source='Linux PCI sysfs driver binding; no bind/unbind'
    else:
        iommu={'address':address,'available':os.path.islink(path+'/iommu_group')}
        if iommu['available']:
            group=os.path.realpath(path+'/iommu_group');number=os.path.basename(group)
            if not number.isdecimal():raise ValueError('group number')
            members=entries(group+'/devices')
            if not all(re.fullmatch(pattern,m) for m in members):raise ValueError('invalid group member')
            iommu.update(group=int(number),members=members)
        else:unavailable.append('iommu_group')
        result['iommu']=iommu
        source='Linux PCI sysfs IOMMU group; absence is not isolation proof'
    publish({'pci':result},source)


if __name__ == "__main__":
    main()
