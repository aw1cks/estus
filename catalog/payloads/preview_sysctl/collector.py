import json
import os
import re
import stat

import estus_runtime

MAX = 9007199254740991
PROJECTION_BOUND = 4096
KEY_PATTERN = re.compile(r'[a-z0-9_]+(?:\.[a-z0-9_-]+)+')


def read_bounded(path, bound=65536):
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError('source is not a regular file')
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(8192, bound + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > bound:
                raise ValueError('source exceeds bound')
        return b''.join(chunks).decode('utf-8', errors='strict')
    finally:
        os.close(fd)


def main():
    args = estus_runtime.request()
    key, value, mode = args[0], args[1], args[2]
    approved_keys = args[3] if len(args) >= 4 else None
    if not isinstance(key, str) or not estus_runtime.allowed(key, approved_keys):
        raise ValueError('unapproved typed sysctl')
    if (
        '..' in key
        or '/' in key
        or KEY_PATTERN.fullmatch(key) is None
        or type(value) is not int
        or not 0 <= value <= MAX
    ):
        raise ValueError('unapproved typed sysctl')
    if key == 'kernel.printk_ratelimit' and not 0 <= value <= 60:
        raise ValueError('unapproved typed sysctl')
    if mode not in ('config', 'runtime'):
        raise ValueError('unsupported sysctl preview mode')

    proc = '/proc/sys/' + key.replace('.', '/')
    runtime_text = read_bounded(proc, 64).strip()
    if not re.fullmatch(r'[0-9]{1,16}', runtime_text):
        raise ValueError('invalid sysctl readback')
    before_runtime = int(runtime_text)

    if mode == 'config':
        slug = key.replace('_', '__').replace('.', '_')
        config_path = '/etc/sysctl.d/90-estus-catalog-' + slug + '.conf'
        after_config = key + ' = ' + str(value) + '\n'
        directory = os.path.dirname(config_path)
        if os.path.realpath(directory) != directory:
            raise ValueError('aliased config directory')
        try:
            st = os.lstat(config_path)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError('unsafe existing config')
            before_config = read_bounded(config_path, 1024)
        except FileNotFoundError:
            before_config = ''
        persistent = True
        changed = (before_runtime != value) or (before_config != after_config)
    else:
        config_path = ''
        before_config = ''
        after_config = ''
        persistent = False
        changed = before_runtime != value

    result = {
        'key': key,
        'mode': mode,
        'before_runtime': before_runtime,
        'after_runtime': value,
        'changed': changed,
        'persistent': persistent,
        'config_path': config_path,
        'before_config': before_config,
        'after_config': after_config,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND:
        raise ValueError('result bound')
    print(encoded)


if __name__ == '__main__':
    main()
