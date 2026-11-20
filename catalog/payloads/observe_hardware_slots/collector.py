import estus_runtime


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
    def run(argv):
        result = estus_runtime.run_bounded(
            argv, timeout=6, max_bytes=65536, accepted=None)
        return result['returncode'], result['stdout'], result['stderr']
    rc,text,error=run([os.environ['ESTUS_EXEC_DMIDECODE'],'--type','9'])
    if rc!=0:raise ValueError('firmware inventory unavailable; provision dmidecode and approved firmware access')
    keys={'Designation': 'designation', 'Type': 'type', 'Current Usage': 'current_usage', 'Length': 'length', 'ID': 'slot_id', 'Bus Address': 'bus_address', 'Data Bus Width': 'data_bus_width'}
    records=[];current=None;selected=False
    for line in text.splitlines():
        m=re.fullmatch(r'Handle (0x[0-9A-Fa-f]{4}), DMI type 9, [0-9]+ bytes',line)
        if m:
            current={'handle':m[1].lower()};records.append(current);selected=False
            if len(records)>256:raise ValueError('firmware record bound')
            continue
        if line=='System Slot Information':selected=True;continue
        if current is None or not selected:continue
        label,sep,value=line.strip().partition(':')
        if sep and label in keys:
            key=keys[label];value=value.strip()
            if key in current:raise ValueError('duplicate firmware field')
            if value.lower() in ('unknown','not specified','not provided','none','other','not installed','no module installed'):
                unavailable.append(current['handle']+'.'+key)
                if value.lower()=='no module installed':current['populated']=False
            else:
                current[key]=value
                if key=='size':current['populated']=True
    if not records:unavailable.append('firmware_records')
    publish({'records':records},'SMBIOS firmware via dmidecode type 9; firmware reports, not authenticated or live capacity')


if __name__ == "__main__":
    main()
