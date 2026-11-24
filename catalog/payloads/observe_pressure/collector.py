import re

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


def psi_boot_parameter(cmdline):
    """Last psi= value on the kernel command line, parsed like kstrtobool; None if absent."""
    value = None
    for token in cmdline.split():
        if not token.startswith('psi='):
            continue
        flag = token[4:6].lower()
        if flag[:1] in ('y', 't', '1') or flag == 'on':
            value = True
        elif flag[:1] in ('n', 'f', '0') or flag == 'of':
            value = False
    return value


def classify_missing_psi(cmdline, config):
    """Explain an absent /proc/pressure as (status, reason or None).

    config is the running kernel's build configuration text, or None when it
    cannot be read. 'disabled' means the kernel has PSI but it is switched off:
    by psi=0 on the command line, or by CONFIG_PSI_DEFAULT_DISABLED without psi=1.
    """
    options = None if config is None else set(config.splitlines())
    if options is not None and 'CONFIG_PSI=y' not in options:
        return 'unsupported', None
    parameter = psi_boot_parameter(cmdline)
    if parameter is False:
        return 'disabled', 'boot_parameter'
    if options is not None and parameter is None and 'CONFIG_PSI_DEFAULT_DISABLED=y' in options:
        return 'disabled', 'kernel_default'
    return 'unsupported', None


def main():
    import os, json, signal, platform, datetime
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('observation deadline')))
    signal.alarm(12)
    if platform.system() != 'Linux':
        raise ValueError('Linux required')
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

    missing = None
    def explain_missing():
        # Best-effort evidence only: an unreadable source leaves the plain 'unsupported'.
        def optional(path, bound):
            try: return read(path, bound).decode('utf-8', 'replace')
            except (OSError, ValueError): return None
        cmdline = optional('/proc/cmdline', 65536) or ''
        config = optional('/boot/config-' + platform.release(), 1048576)
        return classify_missing_psi(cmdline, config)

    entries=[]
    for resource in ('cpu','memory','io'):
        entry={'resource':resource}
        try: data=read('/proc/pressure/'+resource, 2048)
        except FileNotFoundError:
            if missing is None: missing = explain_missing()
            entry['status'] = missing[0]
            if missing[1]: entry['reason'] = missing[1]
        except PermissionError: entry['status']='denied'
        else:
            entry['status']='available'
            entry.update(parse_pressure(data))
        entries.append(entry)
    emit({'scope':'procfs_view','pressure':entries})



if __name__ == "__main__":
    main()
