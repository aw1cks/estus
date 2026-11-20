import estus_runtime
def main():
    import json, os, re
    p=estus_runtime.request()[0]; policy=estus_runtime.request()[1]
    def run(args):
        return estus_runtime.run_bounded(
            [os.environ['ESTUS_EXEC_ETHTOOL']] + args, timeout=6, max_bytes=65536)['stdout']
    dev=p['interface']
    if dev!=policy['interface'] or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',dev): raise ValueError('interface outside operator policy')
    with open('/sys/class/net/'+dev+'/address') as f: mac=f.read(64).strip()
    if mac!=policy['mac']: raise ValueError('interface identity mismatch')
    identity=run(['-i',dev])
    if not re.search(r'^driver: '+re.escape(policy['driver'])+r'$',identity,re.M): raise ValueError('driver outside reviewed policy')
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
    v=selected('-a',['Autonegotiate','RX','TX'])
    emit({'interface':dev,'autoneg':switch(v['Autonegotiate']),'rx':switch(v['RX']),'tx':switch(v['TX']),'source':'ethtool -a; driver-reported flow control, not wire-level proof'})


if __name__ == "__main__":
    main()
