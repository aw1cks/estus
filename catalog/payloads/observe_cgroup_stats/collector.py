def main():
    import os, sys, json, re
    MAX=9007199254740991
    args=[json.loads(x) for x in sys.argv[1:]]
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

    result=context(); result.update(observation(path)); publish(result)


if __name__ == "__main__":
    main()
