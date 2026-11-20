import os, json, re, time
import estus_runtime

MAX=9007199254740991

def parse_cpu_stat(data):
    if len(data)>4096: raise ValueError('cpu counter source bound')
    values={}
    for line in data.decode('ascii').splitlines():
        pair=line.split()
        if len(pair)!=2 or not re.fullmatch('[0-9]{1,16}',pair[1]): raise ValueError('cpu counter format')
        if pair[0] in values: raise ValueError('duplicate cpu counter')
        values[pair[0]]=int(pair[1])
    usage=values['usage_usec']
    if not 0<=usage<=MAX: raise ValueError('CPU counter bound')
    return usage

def sample_cpu(directory):
    # The directory descriptor pins the counter's cgroup generation even if
    # its pathname is removed and recreated while cpu.stat is being read.
    directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        st=os.fstat(directory_fd)
        ident=str(st.st_dev)+':'+str(st.st_ino)
        counter_fd=os.open('cpu.stat',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd)
        with os.fdopen(counter_fd,'rb') as stream:
            data=stream.read(4097)
        return ident,parse_cpu_stat(data)
    finally:
        os.close(directory_fd)

def cpu_observation(previous,ident,usage,elapsed):
    reset=bool(previous and (ident!=previous['identity'] or usage<previous['cpu_usage_usec']))
    item={'elapsed_usec':elapsed,'identity':ident,'cpu_usage_usec':usage,'reset':reset}
    if previous and not reset and elapsed>previous['elapsed_usec']:
        item['cpu_usec_per_second']=(usage-previous['cpu_usage_usec'])*1000000/(elapsed-previous['elapsed_usec'])
    return item


def main():
    args=estus_runtime.request()
    def read(path, bound=65536):
        with open(path,'rb') as f: data=f.read(bound+1)
        if len(data)>bound: raise ValueError('source exceeds bound')
        return data.decode('utf-8',errors='strict').strip()
    def publish(value):
        encoded=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>4096: raise ValueError('result bound')
        print(encoded)

    root=args.pop(0)
    if not re.fullmatch(r'/[A-Za-z0-9_.@:-]+(?:/[A-Za-z0-9_.@:-]+){0,30}',root) or any(x in ('.','..') for x in root.split('/')): raise ValueError('invalid operator-approved subtree')
    base='/sys/fs/cgroup'
    if not os.path.isfile(base+'/cgroup.controllers'): raise ValueError('cgroup v2 unified hierarchy required')
    read(base+'/cgroup.controllers',4096)
    path=base+root
    if os.path.realpath(path)!=path or not os.path.isdir(path): raise ValueError('missing or aliased subtree')
    boot=read('/proc/sys/kernel/random/boot_id',128)
    def optional(directory,name,bound=4096):
        try: return read(directory+'/'+name,bound)
        except FileNotFoundError: return None
    fields={'cpu.stat':'cumulative','cpu.max':'limit','cpu.weight':'limit','memory.current':'gauge','memory.max':'limit','memory.high':'limit','memory.swap.current':'gauge','memory.swap.max':'limit','memory.events':'cumulative','io.stat':'cumulative','pids.current':'gauge','pids.max':'limit','cpu.pressure':'pressure','memory.pressure':'pressure','io.pressure':'pressure','cpuset.cpus.effective':'limit','cpuset.mems.effective':'limit'}
    def observation(directory):
        present=[]; unavailable=[]
        for name,kind in fields.items():
            if name not in {'cpu.stat','cpu.max','memory.current','memory.max','pids.current','pids.max'}: continue
            value=optional(directory,name)
            if value is None: unavailable.append(name)
            else: present.append({'name':name,'kind':kind,'text':value})
        return {'files':present,'unavailable':unavailable}
    def identity(directory):
        st=os.stat(directory)
        return str(st.st_dev)+':'+str(st.st_ino)
    def context():
        ancestors=[]; d=os.path.dirname(path)
        while d.startswith(base):
            values=[]
            for name in ['cpu.max','memory.max','memory.high','pids.max','cpuset.cpus.effective','cpuset.mems.effective','cgroup.controllers','cgroup.subtree_control']:
                value=optional(d,name,4096)
                if value is not None: values.append({'name':name,'value':value})
            ancestors.append({'path':d[len(base):] or '/','constraints':values})
            if d==base: break
            d=os.path.dirname(d)
            if len(ancestors)>32: raise ValueError('ancestor bound')
        return {'root':root,'boot_id':boot,'identity':identity(path),'controllers':read(path+'/cgroup.controllers',4096).split(),'subtree_control':read(path+'/cgroup.subtree_control',4096).split(),'ancestors':ancestors,'scope':'cgroup_v2_visible_hierarchy_nonatomic'}



    duration,count=args
    start=time.monotonic_ns(); first=observation(path); observations=[]; previous=None
    for index in range(count):
        if index: time.sleep(max(0,(start+int(duration*1000000*index/(count-1))-time.monotonic_ns())/1e9))
        ident,usage=sample_cpu(path)
        elapsed=(time.monotonic_ns()-start)//1000
        item=cpu_observation(previous,ident,usage,elapsed)
        observations.append(item); previous=item
    last=observation(path); result=context(); result.update(observations=observations,first=first,last=last); publish(result)


if __name__ == "__main__":
    main()
