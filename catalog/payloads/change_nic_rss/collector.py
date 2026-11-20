import estus_runtime
def main():
    import json, os, re
    p=estus_runtime.request()[0]; policy=estus_runtime.request()[1]
    def run(args):
        return estus_runtime.run_bounded(
            [os.environ['ESTUS_EXEC_ETHTOOL']] + args, timeout=6, max_bytes=65536)['stdout']
    dev=p['interface']
    if (policy['interface'] != '*' and dev != policy['interface']) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', dev): raise ValueError('interface outside operator policy')
    with open('/sys/class/net/'+dev+'/address') as f: mac=f.read(64).strip()
    if policy['mac'] != '*' and mac != policy['mac']: raise ValueError('interface identity mismatch')
    identity=run(['-i',dev])
    if policy['driver'] != '*' and not re.search(r'^driver: ' + re.escape(policy['driver']) + r'$', identity, re.M): raise ValueError('driver outside reviewed policy')
    def selected(flag, labels, section=None):
        values={}; active=section is None
        for line in run([flag,dev]).splitlines():
            line=line.strip()
            if section and line.endswith(':') and line in ('Pre-set maximums:','Current hardware settings:'): active=line==section
            label,sep,value=line.partition(':')
            if active and sep and label in labels:
                if label in values: raise ValueError('duplicate selected field')
                values[label]=value.strip()
        if set(values)!=set(labels): raise ValueError('selected driver capability unavailable')
        return values
    def number(value):
        if not re.fullmatch(r'[0-9]{1,7}',value): raise ValueError('invalid numeric driver field')
        n=int(value)
        if n>1048576: raise ValueError('numeric driver field exceeds bound')
        return n
    def switch(value):
        if value not in ('on','off'): raise ValueError('invalid boolean driver field')
        return value=='on'
    def emit(value):
        raw=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(raw.encode())>4096: raise ValueError('projection bound exceeded')
        print(raw)
    if os.geteuid()!=0 or policy.get('allow_runtime_tuning') is not True: raise ValueError('privileged operator runtime tuning policy required')
    import hashlib
    standard='6d5a56da255b0ec24167253d43a38fb0d0ca2bcbae7b30b477cb2da38030f20c6a42b73bbeac01fa'
    presets={'standard':bytes.fromhex(standard),'rotated':bytes.fromhex(standard[2:]+standard[:2])}
    if p['preset'] not in presets: raise ValueError('RSS key preset outside reviewed policy')
    def observe():
        text=run(['-x',dev]); lines=text.splitlines(); keys=[]
        for i,line in enumerate(lines):
            if line.strip()=='RSS hash key:':
                if i+1>=len(lines): raise ValueError('RSS key absent')
                raw=lines[i+1].strip()
                if not re.fullmatch(r'[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){39}',raw): raise ValueError('reviewed RSS operation requires a 40-byte key')
                keys.append(bytes.fromhex(raw.replace(':','')))
        if len(keys)!=1: raise ValueError('RSS hash key capability unavailable or ambiguous')
        return keys[0]
    before=observe()
    expected=presets[p['preset']]
    run(['-X',dev,'hkey',':'.join(format(n,'02x') for n in expected)])
    after=observe()
    if after!=expected: raise ValueError('RSS key readback mismatch; partial effects possible, no automatic recovery')
    def summary(key): return {'key_bytes':len(key),'key_sha256':hashlib.sha256(key).hexdigest()}
    emit({'interface':dev,'before':summary(before),'after':summary(after),'changed':before!=after,'verified':True,'persistence':'runtime_only'})


if __name__ == "__main__":
    main()
