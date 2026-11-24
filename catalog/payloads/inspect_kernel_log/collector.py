import estus_runtime
def journal_boot_id(value, current):
    """Accept 'current', journald's 32-hex boot ID or the dashed /proc form."""
    import re
    if value == 'current':
        value = current()
    if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}', value):
        value = value.replace('-', '')
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{32}', value):
        raise ValueError('invalid boot')
    return value


def main():
    import os, json, re
    MAX=9007199254740991
    args=estus_runtime.request()
    def run(argv, bound=1048576):
        return estus_runtime.run_bounded(
            argv, timeout=10, max_bytes=bound)['stdout']
    def publish(value):
        encoded=json.dumps(value,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>4096: raise ValueError('result bound')
        print(encoded)

    p=dict(zip(['boot_id', 'since', 'until', 'priority', 'cursor', 'limit'],args))

    if p['since']>p['until']: raise ValueError('inverted time interval')
    if not re.fullmatch(r'[A-Za-z0-9=;_-]{0,256}',p['cursor']): raise ValueError('invalid bounded cursor syntax')
    boot=journal_boot_id(p['boot_id'],estus_runtime.boot_id)
    base=[os.environ['ESTUS_EXEC_JOURNALCTL'],'--no-pager','--quiet','--output=json','--all']
    def records(argv):
        text=run(argv)
        lines=text.splitlines()
        if len(lines)>101: raise ValueError('record count exceeds bound')
        return [json.loads(line) for line in lines]
    status='available'; selected=[]
    # Test the exact cursor globally, before applying a filter that might legitimately match nothing.
    if p['cursor']:
        try:
            probe=records(base+['--cursor='+p['cursor'],'--lines=+1'])
            if not probe or probe[0].get('__CURSOR')!=p['cursor']: status='cursor_unavailable'
            elif probe[0].get('_BOOT_ID')!=boot or not p['since']*1000000<=int(probe[0]['__REALTIME_TIMESTAMP'])<=p['until']*1000000:
                raise ValueError('cursor outside requested boot/time scope')
        except estus_runtime.CommandFailed as error:
            if 'Failed to seek to cursor' not in str(error): raise
            status='cursor_unavailable'
    if status=='available':
        query=base+['--boot='+boot,'--until=@'+str(p['until']),'--priority=0..'+str(p['priority']),'--lines='+('+' if p['cursor'] else '')+str(p['limit']+1)]
        # journalctl rejects --since combined with --after-cursor. The exact
        # cursor probe above must already lie inside the requested boot/time
        # range; forward iteration preserves that lower bound without --since.
        # --until and the kernel transport/priority filters still apply.
        if not p['cursor']: query+=['--since=@'+str(p['since'])]
        query+=['_TRANSPORT=kernel']

        # Forward continuation, not a repeated last-N poll. Initial selection returns the latest bounded records.
        if p['cursor']: query+=['--after-cursor='+p['cursor']]
        selected=records(query)
    truncated=len(selected)>p['limit']
    if p['cursor']: selected=selected[:p['limit']]
    else: selected=selected[-p['limit']:]
    result=[]
    for r in selected:
        def integer(key):
            v=r[key]
            if not isinstance(v,str) or not re.fullmatch('[0-9]{1,16}',v): raise ValueError('invalid journal integer')
            n=int(v)
            if n>MAX: raise ValueError('journal integer bound')
            return n
        msg=r.get('MESSAGE','')
        if isinstance(msg,list) and all(type(x) is int and 0<=x<=255 for x in msg): msg=bytes(msg).decode('utf-8','replace')
        if not isinstance(msg,str): raise ValueError('unsupported journal message encoding')
        item={'cursor':r['__CURSOR'],'boot_id':r['_BOOT_ID'],'realtime_usec':integer('__REALTIME_TIMESTAMP'),'monotonic_usec':integer('__MONOTONIC_TIMESTAMP'),'message':msg[:256],'message_truncated':len(msg)>256}
        if len(item['cursor'])>256 or item['boot_id']!=boot: raise ValueError('unexpected journal identity')
        for src,dst,bound in [('_SYSTEMD_UNIT','unit',256),('_TRANSPORT','transport',32)]:
            if src in r:
                if not isinstance(r[src],str) or len(r[src])>bound: raise ValueError('journal field bound')
                item[dst]=r[src]
        if 'PRIORITY' in r:
            item['priority']=integer('PRIORITY')
            if item['priority']>7: raise ValueError('priority bound')
        result.append(item)
    publish({'boot_id':boot,'scope':'kernel_transport_only','status':status,'records':result,'continuation_cursor':result[-1]['cursor'] if result else p['cursor'],'truncated':truncated,'incomplete':True,'incomplete_reason':'retained accessible journal only; history may expire; concurrent writes are not atomic','since':p['since'],'until':p['until'],'priority_max':p['priority']})


if __name__ == "__main__":
    main()
