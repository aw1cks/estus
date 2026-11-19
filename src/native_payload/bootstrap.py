"""Packaged stdin-only payload protocol. Never imports caller data as code."""
import hashlib
import importlib.util
import json
import os
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import time

MAX_JSON = 262144
MAX_SOURCE = 1048576

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result

def loads(raw):
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))

def exact(n):
    data = sys.stdin.buffer.read(n)
    if len(data) != n:
        raise ValueError('truncated frame')
    return data

def file_identity(path):
    st = os.stat(path)
    return [os.path.realpath(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns]

def identity(requirements):
    if list(sys.version_info[:2]) < requirements['python_min']:
        raise ValueError('unsupported interpreter')
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
        boot = stream.read(128).strip()
    result = {'uid': os.geteuid(), 'gid': os.getegid(), 'boot': boot,
              'python': file_identity(sys.executable), 'version': list(sys.version_info[:3]),
              'modules': {}, 'executables': {}, 'paths': {}}
    for module in requirements['modules']:
        spec = importlib.util.find_spec(module)
        if spec is None:
            raise ValueError('missing module')
        result['modules'][module] = file_identity(spec.origin) if spec.origin and os.path.isfile(spec.origin) else spec.origin
    for program in requirements['executables']:
        path = shutil.which(program)
        if not path:
            raise ValueError('missing executable')
        result['executables'][program] = file_identity(path)
    for path in requirements['paths']:
        result['paths'][path] = file_identity(path)
    return result

class Interrupted(Exception):
    pass

def interrupted(_signal, _frame):
    raise Interrupted()

for interruption_signal in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(interruption_signal, interrupted)

def run():
    if exact(8) != b'ESTUSNP1':
        raise ValueError('protocol')
    n, size = struct.unpack('!II', exact(8))
    if not 0 < n <= MAX_JSON or size > MAX_SOURCE:
        raise ValueError('frame bounds')
    spec = loads(exact(n))
    source = exact(size)
    if sys.stdin.buffer.read(1):
        raise ValueError('trailing frame')
    if spec['schema'] != 1 or spec['operation'] not in ('discover', 'execute'):
        raise ValueError('protocol')
    response = {'schema': 1, 'id': spec['id'], 'phase': 'rejected'}
    try:
        observed = identity(spec['requirements'])
        response['identity'] = observed
        if spec['operation'] == 'discover':
            if source:
                raise ValueError('discovery source')
            response['phase'] = 'discovered'
            return response, 0
        if observed != spec['identity']:
            response['identity_mismatch'] = True
            raise ValueError('identity drift')
        if hashlib.sha256(source).hexdigest() != spec['sha256']:
            raise ValueError('source drift')
        argv = spec['argv']
        if not isinstance(argv, list) or len(argv) > 64 or any(not isinstance(x, str) or '\0' in x for x in argv):
            raise ValueError('argv')
        timeout = spec['timeout']
        limit = spec['output_limit']
        if not 0 < timeout <= 600 or not 0 < limit <= 16777216:
            raise ValueError('bounds')
        deadline = time.monotonic() + timeout
        # Source is immutable verified bytes, never a pathname reopened after approval.
        child = subprocess.Popen([sys.executable, '-I', '-', *argv], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        response['phase'] = 'started'
        sel = selectors.DefaultSelector()
        for pipe, name in [(child.stdin, 'stdin'), (child.stdout, 'stdout'), (child.stderr, 'stderr')]:
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_WRITE if name == 'stdin' else selectors.EVENT_READ, name)
        offset = 0
        output = {'stdout': bytearray(), 'stderr': bytearray()}
        overflow = False
        try:
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                for key, _ in sel.select(min(remaining, .1)):
                    pipe, name = key.fileobj, key.data
                    if name == 'stdin':
                        try:
                            offset += os.write(pipe.fileno(), source[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(source)
                        if offset == len(source):
                            sel.unregister(pipe)
                            pipe.close()
                    else:
                        chunk = os.read(pipe.fileno(), 65536)
                        if not chunk:
                            sel.unregister(pipe)
                            pipe.close()
                        else:
                            available = max(0, limit - len(output[name]))
                            output[name].extend(chunk[:available])
                            overflow = overflow or len(chunk) > available
            rc = child.wait(timeout=max(.001, deadline - time.monotonic()))
            response.update(phase='complete', rc=rc, overflow=overflow)
            if overflow:
                response['output_status'] = 'overflow'
            else:
                try:
                    response['stdout'] = output['stdout'].decode('utf-8', errors='strict')
                    response['output_status'] = 'complete'
                except UnicodeDecodeError:
                    response['output_status'] = 'invalid_utf8'
            # stderr is drained but never published; it can contain secrets.
            return response, 0 if rc == 0 else 1
        finally:
            sel.close()
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait()
    except (TimeoutError, subprocess.TimeoutExpired):
        response['phase'] = 'timeout'
        return response, 124
    except Interrupted:
        response['phase'] = 'cancelled'
        return response, 125
    except Exception:
        # No exception text or caller/source values cross the protocol boundary.
        return response, 70

try:
    response, rc = run()
except Exception:
    response, rc = {'schema': 1, 'phase': 'rejected'}, 70
sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False, separators=(',', ':')) + '\n')
sys.stdout.flush()
sys.exit(rc)
