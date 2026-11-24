import estus_runtime

MAX_TABLE = 65536


def parse_rss(text):
    """Parse `ethtool -x` output into (indirection table, hash functions); the key is skipped."""
    import re
    table = []
    functions = []
    mode = ''
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('RSS hash key:'): mode = 'key'; continue
        if line.startswith('RSS hash function:'): mode = 'functions'; continue
        if line.startswith('RSS input transformation:'): mode = 'other'; continue
        if mode == 'functions':
            m = re.fullmatch(r'([A-Za-z0-9_-]{1,64}):\s*(on|off)', line)
            if m:
                functions.append({'name': m[1], 'enabled': m[2] == 'on'})
                if len(functions) > 32: raise ValueError('hash function bound')
        elif mode == '':
            m = re.fullmatch(r'([0-9]+):\s+([0-9 ]+)', line)
            if m:
                if int(m[1]) != len(table): raise ValueError('noncontiguous RSS table')
                for n in m[2].split():
                    if int(n) > 65535: raise ValueError('queue bound')
                    table.append(int(n))
                    if len(table) > MAX_TABLE: raise ValueError('RSS table bound')
    return table, functions


def page_rss(base, table, offset, budget=4096, max_nodes=256):
    """Complete summary plus one page of the indirection table starting at offset.

    indirection_size and queue_entries (slots per queue, indexed by queue) always
    cover the whole table; indirection holds as many entries from offset as fit,
    and next_offset is present while entries remain.
    """
    import json
    if type(offset) is not int or not 0 <= offset < MAX_TABLE:
        raise ValueError('offset out of bounds')
    queues = [0] * (max(table) + 1 if table else 0)
    for queue in table:
        queues[queue] += 1
    page = dict(base, indirection_size=len(table), queue_entries=queues, offset=offset,
                indirection=[], truncated=False, omitted_records=0)
    def fits():
        def nodes(v):
            if isinstance(v, dict): return 1 + sum(nodes(x) for x in v.values())
            if isinstance(v, list): return 1 + sum(nodes(x) for x in v)
            return 1
        # Leave room for next_offset and the final truncated/omitted values.
        return len(json.dumps(page, separators=(',', ':')).encode()) <= budget - 64 and nodes(page) < max_nodes
    if not fits(): raise ValueError('RSS summary exceeds projection budget')
    for queue in table[offset:]:
        page['indirection'].append(queue)
        if not fits():
            page['indirection'].pop()
            break
    end = offset + len(page['indirection'])
    if end < len(table):
        page['next_offset'] = end
    page['truncated'] = len(page['indirection']) < len(table)
    page['omitted_records'] = len(table) - len(page['indirection'])
    return page


def main():
    import json, os, re, datetime
    def check(v):
        if isinstance(v,bool) or v is None: return
        if isinstance(v,int):
            if not 0<=v<=9007199254740991: raise ValueError('integer bound')
        elif isinstance(v,str):
            if len(v)>4096 or any(ord(c)<32 for c in v): raise ValueError('string bound')
        elif isinstance(v,list):
            if len(v)>MAX_TABLE: raise ValueError('entry bound')
            for x in v: check(x)
        elif isinstance(v,dict):
            if len(v)>256: raise ValueError('field bound')
            for k,x in v.items(): check(k);check(x)
        else: raise ValueError('type')
    def run(argv):
        result = estus_runtime.run_bounded(
            argv, timeout=6, max_bytes=1048576, accepted=None)
        return result['returncode'], result['stdout'], result['stderr']
    interface, offset = estus_runtime.request()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}',interface):raise ValueError('interface')
    if not os.path.isdir('/sys/class/net/'+interface):raise ValueError('interface absent')
    rc,text,error=run([os.environ['ESTUS_EXEC_ETHTOOL'],'-x',interface])
    table=[];functions=[];unavailable=[]
    if rc==0:
        table,functions=parse_rss(text)
    elif not any(x in (text+error).lower() for x in ('not supported','cannot get','operation not permitted')):
        raise ValueError('RSS query failed')
    if not table:unavailable.append('indirection')
    if not functions:unavailable.append('hash_functions')
    base={'source':'ethtool -x; hash key deliberately excluded',
          'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
          'unavailable':unavailable,'interface':interface,'supported':rc==0,'hash_functions':functions}
    check(base);check(table)
    print(json.dumps(page_rss(base,table,offset),separators=(',',':')))


if __name__ == "__main__":
    main()
