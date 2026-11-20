import estus_runtime
def main():
    import json, os, ipaddress, socket, struct
    p = {k:v for k,v in estus_runtime.request()[0].items() if v is not None}
    policy = estus_runtime.request()[1]
    def emit(value):
        def measure(v,depth=0):
            if depth>8: raise ValueError('result depth exceeded')
            if isinstance(v,str) and len(v)>512: raise ValueError('result string exceeded')
            if isinstance(v,int) and not isinstance(v,bool) and not 0<=v<=9007199254740991: raise ValueError('result integer exceeded')
            if isinstance(v,dict):
                if len(v)>32: raise ValueError('result object exceeded')
                return 1+sum(measure(x,depth+1) for x in v.values())
            if isinstance(v,list):
                if len(v)>128: raise ValueError('result entries exceeded')
                return 1+sum(measure(x,depth+1) for x in v)
            return 1
        while True:
            nodes=measure(value)
            raw=json.dumps(value,separators=(',',':'),allow_nan=False,ensure_ascii=True)
            if nodes<=256 and len(raw.encode('ascii'))<=4096: break
            raise ValueError('result exceeds projection budget')
        print(raw)

    name=p['name']; resolver=p.get('resolver') or policy.get('resolver')
    if policy.get('resolver') and resolver!=policy['resolver']: raise ValueError('DNS target outside operator policy')
    if policy.get('dns_names') and '*' not in policy['dns_names'] and name not in policy['dns_names']: raise ValueError('DNS target outside operator policy')
    port=policy.get('dns_port') if policy.get('dns_port') is not None else 53
    qtype={'A':1,'AAAA':28}[p['type']]
    ident=int.from_bytes(os.urandom(2),'big')
    question=b''.join(bytes([len(x)])+x.encode('ascii') for x in name.split('.'))+b'\x00'+struct.pack('!HH',qtype,1)
    query=struct.pack('!HHHHHH',ident,256,1,0,0,0)+question
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.connect((resolver,port))
        sock.send(query)
        data=sock.recv(4097)
    if len(data)>4096 or len(data)<12: raise ValueError('DNS response size invalid')
    rid,flags,qd,an,ns,ar=struct.unpack('!HHHHHH',data[:12])
    if rid!=ident or not flags&32768 or flags&512 or qd!=1 or an>32 or ns+ar>64: raise ValueError('DNS response outside contract')
    def skip_name(offset):
        start=offset
        for _ in range(128):
            if offset>=len(data): raise ValueError('truncated DNS name')
            n=data[offset]; offset+=1
            if n==0: return offset
            if n&192==192:
                if offset>=len(data): raise ValueError('truncated DNS pointer')
                return offset+1
            if n>63: raise ValueError('invalid DNS label')
            offset+=n
            if offset-start>255: raise ValueError('DNS name bound')
        raise ValueError('DNS label count bound')
    off=skip_name(12)
    if data[off:off+4]!=struct.pack('!HH',qtype,1): raise ValueError('DNS question mismatch')
    off+=4
    addresses=[]
    for _ in range(an):
        off=skip_name(off)
        if off+10>len(data): raise ValueError('truncated DNS record')
        typ,cls,ttl,n=struct.unpack('!HHIH',data[off:off+10]); off+=10
        if off+n>len(data): raise ValueError('truncated DNS data')
        if cls==1 and typ==qtype and n==({1:4,28:16}[qtype]): addresses.append(str(ipaddress.ip_address(data[off:off+n])))
        off+=n
    emit({'name':name,'type':p['type'],'resolver':resolver,'rcode':flags&15,'addresses':addresses})


if __name__ == "__main__":
    main()
