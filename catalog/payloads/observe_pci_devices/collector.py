import estus_runtime

MAX_DEVICES = 4096


def page_devices(base, devices, offset, budget=4096, max_nodes=256):
    """One page of address-sorted devices from offset, filled to the projection budget.

    next_offset is present while devices remain; omitted_records counts every
    device not on this page.
    """
    import json
    if type(offset) is not int or not 0 <= offset < MAX_DEVICES:
        raise ValueError('offset out of bounds')
    page = dict(base, devices=[], device_count=len(devices), offset=offset, truncated=False, omitted_records=0)
    def nodes(v):
        if isinstance(v, dict): return 1 + sum(nodes(x) for x in v.values())
        if isinstance(v, list): return 1 + sum(nodes(x) for x in v)
        return 1
    def fits():
        # Leave room for next_offset and the final truncated/omitted values.
        return len(json.dumps(page, separators=(',', ':')).encode()) <= budget - 64 and nodes(page) < max_nodes
    if not fits(): raise ValueError('selected record exceeds projection budget')
    for device in devices[offset:]:
        page['devices'].append(device)
        if not fits():
            page['devices'].pop()
            if not page['devices']: raise ValueError('selected record exceeds projection budget')
            break
    end = offset + len(page['devices'])
    if end < len(devices):
        page['next_offset'] = end
    page['truncated'] = len(page['devices']) < len(devices)
    page['omitted_records'] = len(devices) - len(page['devices'])
    return page


def main():
    import json, os, re, datetime
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
                if len(result)>MAX_DEVICES: raise ValueError('entry bound')
        return sorted(result)
    def check(v):
        if isinstance(v,bool) or v is None: return
        if isinstance(v,int):
            if not 0<=v<=9007199254740991: raise ValueError('integer bound')
        elif isinstance(v,str):
            if len(v)>4096 or any(ord(c)<32 for c in v): raise ValueError('string bound')
        elif isinstance(v,list):
            if len(v)>MAX_DEVICES: raise ValueError('entry bound')
            for x in v: check(x)
        elif isinstance(v,dict):
            if len(v)>256: raise ValueError('field bound')
            for k,x in v.items(): check(k);check(x)
        else: raise ValueError('type')
    offset=estus_runtime.request()[0]
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
    devices=[device(n) for n in entries(root)]
    base=dict(source='Linux PCI sysfs numeric identities',observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),unavailable=unavailable)
    check(base);check(devices)
    print(json.dumps(page_devices(base,devices,offset),separators=(',',':')))


if __name__ == "__main__":
    main()
