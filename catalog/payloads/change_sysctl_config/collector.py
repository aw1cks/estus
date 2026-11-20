import estus_runtime
def main():
    import os, json, re, stat
    MAX=9007199254740991
    args=estus_runtime.request()
    def read(path, bound=65536):
        with open(path,'rb') as f: data=f.read(bound+1)
        if len(data)>bound: raise ValueError('source exceeds bound')
        return data.decode('utf-8',errors='strict').strip()
    def run(argv, bound=1048576):
        return estus_runtime.run_bounded(
            argv, timeout=10, max_bytes=bound)['stdout']
    def publish(value):
        encoded=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>4096: raise ValueError('result bound')
        print(encoded)

    key,value=args[0],args[1]
    if not isinstance(key,str): raise ValueError('unapproved typed sysctl')
    approved_keys=args[2] if len(args)>=3 else None
    if not isinstance(approved_keys,list) or not approved_keys or ('*' not in approved_keys and key not in approved_keys): raise ValueError('unapproved typed sysctl')
    if ('..' in key or '/' in key or not re.fullmatch(r'[a-z0-9_]+(?:\.[a-z0-9_-]+)+',key)
            or type(value) is not int or not 0<=value<=MAX):
        raise ValueError('unapproved typed sysctl')
    if key=='kernel.printk_ratelimit' and not 0<=value<=60:
        raise ValueError('unapproved typed sysctl')
    proc='/proc/sys/'+key.replace('.','/')
    def current():
        text=read(proc,64)
        if not re.fullmatch('[0-9]{1,16}',text): raise ValueError('invalid sysctl readback')
        return int(text)
    before=current()

    import tempfile
    slug=key.replace('_','__').replace('.','_')
    path='/etc/sysctl.d/90-estus-catalog-'+slug+'.conf'
    content=key+' = '+str(value)+'\n'
    directory=os.path.dirname(path)
    if os.path.realpath(directory)!=directory: raise ValueError('aliased config directory')
    try:
        st=os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1: raise ValueError('unsafe existing config')
    except FileNotFoundError: pass
    fd,temporary=tempfile.mkstemp(prefix='.estus-catalog-',dir=directory)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o644); f.write(content); f.flush(); os.fsync(f.fileno())
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    if read(path,1024)!=content.strip(): raise ValueError('persistent readback mismatch')
    # Apply exactly this file. Never --system or an unrelated all-settings reload.
    run([os.environ['ESTUS_EXEC_SYSCTL'],'--load='+path],4096)

    after=current()
    if after!=value: raise ValueError('runtime readback mismatch; operation may already have effects')
    publish({'key':key,'before':before,'value':after,'verified':True,'persistent':True,'application':'exact_config_file_sysctl_load','config_path':path,'atomic_compare_exchange':False,'rollback_guaranteed':False})


if __name__ == "__main__":
    main()
