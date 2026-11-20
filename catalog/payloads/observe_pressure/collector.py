import re
import estus_runtime

MAX = 9007199254740991


def parse_pressure(data):
    if len(data) > 2048: raise ValueError('source exceeds read bound')
    entry = {}
    for line in data.decode('utf-8', 'strict').splitlines():
        match=re.fullmatch(r'(some|full) avg10=([0-9]+\.[0-9]+) avg60=([0-9]+\.[0-9]+) avg300=([0-9]+\.[0-9]+) total=([0-9]+)',line)
        if not match or match[1] in entry: raise ValueError('malformed PSI')
        averages=[float(match[i]) for i in (2,3,4)]
        if any(not 0 <= x <= 100 for x in averages): raise ValueError('PSI average outside range')
        total = int(match[5])
        if not 0 <= total <= MAX: raise ValueError('integer outside projection bound')
        entry[match[1]]=dict(zip(('avg10_percent','avg60_percent','avg300_percent'),averages),total_microseconds=total)
    if 'some' not in entry: raise ValueError('PSI some missing')
    return entry


def main():
    import os, json, re, signal, platform, datetime, errno
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('observation deadline')))
    signal.alarm(12)
    if platform.system() != 'Linux':
        raise ValueError('Linux required')
    args = estus_runtime.request()[0]
    def read(path, bound=65536, directory=None):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream: data = stream.read(bound + 1)
        if len(data) > bound: raise ValueError('source exceeds read bound')
        return data
    def bounded(value, maximum=256):
        if len(value) > maximum: raise ValueError('string exceeds projection bound')
        return value
    def emit(value):
        value['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds')
        data = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(data.encode()) > 4096: raise ValueError('output exceeds bound')
        print(data)

    entries=[]
    for resource in ('cpu','memory','io'):
        entry={'resource':resource}
        try: data=read('/proc/pressure/'+resource, 2048)
        except FileNotFoundError: entry['status']='unsupported'
        except PermissionError: entry['status']='denied'
        else:
            entry['status']='available'
            entry.update(parse_pressure(data))
        entries.append(entry)
    emit({'scope':'procfs_view','pressure':entries})



if __name__ == "__main__":
    main()
