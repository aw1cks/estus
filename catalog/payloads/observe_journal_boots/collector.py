import estus_runtime
def main():
    import os, json, re
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

    limit=args[0]
    text=run([os.environ['ESTUS_EXEC_JOURNALCTL'],'--list-boots','--no-pager','--quiet'],262144)
    lines=text.splitlines()
    if len(lines)>2048: raise ValueError('boot source count bound')
    boots=[]
    for line in lines:
        if re.fullmatch(r'\s*IDX\s+BOOT ID\s+FIRST ENTRY\s+LAST ENTRY\s*',line): continue
        match=re.fullmatch(r'\s*(-?[0-9]{1,10})\s+([0-9a-f]{32})\s+(.{1,256})',line)
        if not match: raise ValueError('unexpected boot listing')
        index=int(match[1])
        if not -2147483648<=index<=2147483647: raise ValueError('boot index bound')
        boots.append({'index':index,'boot_id':match[2],'retained_range_text':match[3]})
    publish({'boots':boots[-limit:],'truncated':len(boots)>limit,'incomplete':True})


if __name__ == "__main__":
    main()
