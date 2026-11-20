"""Packaged stdin-only payload protocol. Never imports caller data as code."""
import base64
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
MAX_SOURCE = 4194304

COLLECTOR_RUNTIME = r"""
def _exact(stream, count):
    data = stream.read(count)
    if len(data) != count:
        raise ValueError('truncated collector frame')
    return data

def _decode_request(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return raw

def _make_runtime(request_values):
    mod = types.ModuleType('estus_runtime')

    def request():
        return list(request_values)
    def read_bytes(path, maximum=4096, optional=False):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if optional:
                return None
            raise
        try:
            data = os.read(fd, maximum + 1)
        finally:
            os.close(fd)
        if len(data) > maximum:
            raise ValueError('source exceeds bound')
        return data

    def check_text(value, maximum=4096):
        if not isinstance(value, str) or len(value) > maximum or '\x00' in value:
            raise ValueError('invalid or oversized source string')
        return value

    def allowed(value, allowlist):
        if not isinstance(allowlist, list) or not allowlist:
            return False
        if not isinstance(value, str) or not value:
            return False
        return '*' in allowlist or value in allowlist

    def boot_id():
        raw = read_bytes('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}', raw):
            raise ValueError('invalid boot_id')
        return raw

    def emit(value, maximum=4096):
        raw = json.dumps(value, separators=(',', ':'), allow_nan=False)
        if len(raw.encode('utf-8')) > maximum:
            raise ValueError('projection bound exceeded')
        print(raw)

    def run_bounded(argv, timeout=15, max_bytes=262144, accepted=(0,)):
        # One bounded-subprocess implementation: session leader, deadline killpg,
        # both streams bounded, strict UTF-8 stdout, classified failures.
        if not isinstance(argv, (list, tuple)) or not argv:
            raise ValueError('invalid argv')
        for value in argv:
            if not isinstance(value, str) or not value or '\x00' in value:
                raise ValueError('invalid argv entry')
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= 600:
            raise ValueError('invalid timeout')
        if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or not 0 < max_bytes <= 16777216:
            raise ValueError('invalid output bound')
        if accepted is not None and not isinstance(accepted, (list, tuple)):
            raise ValueError('invalid accepted statuses')
        fsize_cap = max(262144, max_bytes + 65536)
        def _limits():
            os.setsid()
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_cap, fsize_cap))
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            proc = subprocess.Popen(
                list(argv),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                preexec_fn=_limits,
                close_fds=True,
            )
            timed_out = False
            try:
                rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                rc = proc.wait()
            out.seek(0)
            err.seek(0)
            data = out.read(max_bytes + 1)
            errors = err.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise ValueError('subprocess output exceeds bound')
            if len(errors) > max_bytes:
                errors = errors[:max_bytes]
            stdout = data.decode('utf-8', 'strict')
            stderr = errors.decode('utf-8', 'replace')
        if timed_out:
            raise TimeoutError('subprocess deadline exceeded')
        if accepted is not None and rc not in accepted:
            raise RuntimeError('subprocess failed with exit ' + str(rc) + ': ' + stderr.strip()[:1024])
        return {'returncode': rc, 'timed_out': timed_out, 'stdout': stdout, 'stderr': stderr}

    def run_or_exit(argv, timeout=15, max_bytes=262144, accepted=(0,)):
        # Published collectors report a closed estus_error document instead of a traceback.
        try:
            return run_bounded(argv, timeout=timeout, max_bytes=max_bytes, accepted=accepted)
        except TimeoutError:
            code = 'timeout'
        except RuntimeError:
            code = 'dependency_unavailable'
        except ValueError:
            code = 'policy_violation'
        print(json.dumps({'estus_error': {'code': code}}, separators=(',', ':')))
        sys.exit(1)

    mod.request = request
    mod.read = read_bytes
    mod.read_bytes = read_bytes
    mod.check_text = check_text
    mod.allowed = allowed
    mod.boot_id = boot_id
    mod.emit = emit
    mod.run_bounded = run_bounded
    mod.run_or_exit = run_or_exit
    return mod
"""
COLLECTOR_HARNESS = (
    "import json, os, re, resource, signal, struct, subprocess, sys, tempfile, types\n"
    "FRAME_MAGIC = b'ESTUSCL1'\n"
    "MAX_REQUEST = 65536\n"
    + COLLECTOR_RUNTIME
    + r"""_header = _exact(sys.stdin.buffer, 16)
if _header[:8] != FRAME_MAGIC:
    raise ValueError('collector frame')
_source_len, _request_len = struct.unpack('!II', _header[8:])
if not 0 < _source_len <= 4194304 or _request_len > MAX_REQUEST:
    raise ValueError('collector frame bounds')
_source = _exact(sys.stdin.buffer, _source_len)
_request_raw = _exact(sys.stdin.buffer, _request_len)
if sys.stdin.buffer.read(1):
    raise ValueError('trailing collector frame')
sys.stdin.close()
_request = json.loads(_request_raw.decode('utf-8', 'strict')) if _request_raw else []
if (not isinstance(_request, list) or len(_request) > 64
        or any(not isinstance(value, str) or not value for value in _request)):
    raise ValueError('invalid collector request')
sys.modules['estus_runtime'] = _make_runtime([_decode_request(value) for value in _request])
sys.argv = ['-']
exec(compile(_source, '<estus_collector>', 'exec'), {'__name__': '__main__'})
"""
)
ANSIBALLZ_HARNESS = r"""import datetime, json, os, shutil, sys, tempfile
payload = json.loads(sys.stdin.buffer.read().decode('utf-8'))
sys.stdin = open(os.devnull, 'r')
tmpdir = os.path.realpath(tempfile.mkdtemp(prefix='estus_abz_'))
try:
    os.chmod(tmpdir, 0o700)
    params = payload['params']
    params['ANSIBLE_MODULE_ARGS']['_ansible_tmpdir'] = tmpdir
    ns = {}
    exec(compile(payload['wrapper'], 'ansiballz_wrapper.py', 'exec'), ns)
    ns['_ansiballz_main'](
        zip_data=payload['zip_data'],
        ansible_module=payload['ansible_module'],
        module_fqn=payload['module_fqn'],
        params=json.dumps(params),
        profile=payload['profile'],
        date_time=datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
        extensions={},
        rlimit_nofile=0,
    )
finally:
    shutil.rmtree(tmpdir, ignore_errors=True)
"""

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

ALLOWED_EXEC_DIRS = ('/usr/sbin', '/usr/bin', '/sbin', '/bin', '/usr/lib/systemd')
def detect_pkg_mgr():
    if os.path.exists('/run/ostree-booted'):
        return 'atomic_container'
    os_rel = ''
    try:
        with open('/etc/os-release', 'r', encoding='utf-8', errors='replace') as stream:
            os_rel = stream.read(8192).lower()
    except OSError:
        pass
    if ('id=debian' in os_rel or 'id=ubuntu' in os_rel or 'debian' in os_rel) and os.path.exists('/usr/bin/apt-get'):
        return 'apt'
    for candidate in ('/usr/bin/dnf', '/usr/bin/microdnf'):
        if os.path.exists(candidate):
            return 'dnf5' if os.path.realpath(candidate).endswith('/dnf5') else 'dnf'
    for path, mgr in (
        ('/usr/bin/apt-get', 'apt'),
        ('/usr/bin/yum', 'dnf'),
        ('/usr/bin/zypper', 'zypper'),
        ('/sbin/apk', 'apk'),
        ('/usr/bin/apk', 'apk'),
        ('/usr/bin/pacman', 'pacman'),
    ):
        if os.path.exists(path):
            return mgr
    return 'unknown'


def normalize_exec_name(name):
    if not isinstance(name, str) or not name or len(name) > 64:
        raise ValueError('invalid executable name')
    for ch in name:
        if not (('a' <= ch <= 'z') or ('A' <= ch <= 'Z') or ('0' <= ch <= '9') or ch in ('_', '-')):
            raise ValueError('invalid executable name')
    return name.upper().replace('-', '_')

def resolve_identity(requirements):
    if list(sys.version_info[:2]) < requirements['python_min']:
        raise ValueError('unsupported interpreter')
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
        boot = stream.read(128).strip()
    result = {'uid': os.geteuid(), 'gid': os.getegid(), 'boot': boot,
              'python': file_identity(sys.executable), 'version': list(sys.version_info[:3]),
              'pkg_mgr': detect_pkg_mgr(),
              'modules': {}, 'executables': {}, 'paths': {}}
    for module in requirements['modules']:
        if module == 'estus_runtime':
            result['modules'][module] = '<synthetic>'
            continue
        spec = importlib.util.find_spec(module)
        if spec is None:
            raise ValueError('missing module')
        result['modules'][module] = file_identity(spec.origin) if spec.origin and os.path.isfile(spec.origin) else spec.origin
    for program in requirements['executables']:
        path = shutil.which(program)
        if not path:
            raise ValueError('missing executable')
        result['executables'][program] = file_identity(path)
    candidates_map = requirements.get('executable_candidates') or {}
    if not isinstance(candidates_map, dict) or len(candidates_map) > 64:
        raise ValueError('invalid executable_candidates')
    selected_execs = {}
    if candidates_map:
        result['executable_candidates'] = {}
        seen_norm = set()
        for name, candidates in candidates_map.items():
            norm = normalize_exec_name(name)
            if norm in seen_norm:
                raise ValueError('executable candidate normalization collision')
            seen_norm.add(norm)
            if not isinstance(candidates, list) or not (1 <= len(candidates) <= 8):
                raise ValueError('invalid executable candidates list')
            selected = None
            for path in candidates:
                if (not isinstance(path, str) or not path or len(path) > 4096 or '\0' in path
                        or not path.startswith('/') or '..' in path.split('/')
                        or os.path.dirname(path) not in ALLOWED_EXEC_DIRS):
                    raise ValueError('invalid executable candidate path')
                if selected is None and os.path.isfile(path) and os.access(path, os.X_OK):
                    selected = path
            if selected is None:
                raise ValueError('missing executable candidate')
            result['executable_candidates'][name] = file_identity(selected)
            selected_execs[norm] = selected
    for path in requirements['paths']:
        result['paths'][path] = file_identity(path)
    return result, selected_execs

def identity(requirements):
    return resolve_identity(requirements)[0]

class Interrupted(Exception):
    pass

def interrupted(_signal, _frame):
    raise Interrupted()

for interruption_signal in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
    signal.signal(interruption_signal, interrupted)


def classify_stderr_exception(stderr_bytes, stdout_bytes=b''):
    if stdout_bytes:
        try:
            doc = json.loads(stdout_bytes.decode('utf-8', errors='replace'))
            if isinstance(doc, dict) and isinstance(doc.get('msg'), str):
                msg = doc['msg'].lower()
                if any(tok in msg for tok in ('python3-apt', 'python-apt', 'python3-dnf', 'libdnf5', 'could not import python modules', 'no module named')):
                    return 'dependency_unavailable'
                if 'permission denied' in msg or 'operation not permitted' in msg:
                    return 'permission_denied'
                if 'no package' in msg or 'not found' in msg or 'unable to locate package' in msg:
                    return 'target_not_found'
        except Exception:
            pass
    text = stderr_bytes.decode('utf-8', errors='replace')
    for line in reversed(text.splitlines()):
        head = line.strip().split(':', 1)[0].strip()
        if head == 'PermissionError':
            return 'permission_denied'
        if head == 'FileNotFoundError':
            return 'target_not_found'
        if head in ('TimeoutError', 'subprocess.TimeoutExpired'):
            return 'timeout'
        if head == 'ValueError':
            return 'policy_violation'
        if head == 'RuntimeError':
            return 'dependency_unavailable'
    return None

SAFE_ENV_KEYS = ('PATH', 'HOME', 'USER', 'LOGNAME', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')

def build_child_env(selected_execs, utf8_locale=False):
    env = {}
    for key in SAFE_ENV_KEYS:
        if key in os.environ:
            env[key] = os.environ[key]
    env.setdefault('PATH', '/usr/sbin:/usr/bin:/sbin:/bin')
    if utf8_locale:
        env['LC_ALL'] = 'C.UTF-8'
        env['LANG'] = 'C.UTF-8'
        env['DEBIAN_FRONTEND'] = 'noninteractive'
    else:
        env['LC_ALL'] = 'C'
        env['LANG'] = 'C'
    env['TZ'] = 'UTC'
    for norm, selected_path in selected_execs.items():
        env['ESTUS_EXEC_' + norm] = selected_path
    return env
MAX_REQUEST = 65536
COLLECTOR_FRAME = b'ESTUSCL1'

def collector_frame(source, request):
    raw = json.dumps(request, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')
    if len(raw) > MAX_JSON:
        raise ValueError('request frame bounds')
    return COLLECTOR_FRAME + struct.pack('!II', len(source), len(raw)) + source + raw

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
    if spec['schema'] != 1 or spec['operation'] not in ('discover', 'execute', 'ansiballz'):
        raise ValueError('protocol')
    response = {'schema': 1, 'id': spec['id'], 'phase': 'rejected'}
    try:
        observed, selected_execs = resolve_identity(spec['requirements'])
        response['identity'] = observed
        if spec['operation'] == 'discover':
            if source:
                raise ValueError('discovery source')
            response['phase'] = 'discovered'
            return response, 0
        if observed != spec['identity']:
            response['identity_mismatch'] = True
            raise ValueError('identity drift')
        timeout = spec['timeout']
        limit = spec['output_limit']
        if not 0 < timeout <= 600 or not 0 < limit <= 16777216:
            raise ValueError('bounds')
        deadline = time.monotonic() + timeout
        if spec['operation'] == 'execute':
            if hashlib.sha256(source).hexdigest() != spec['sha256']:
                raise ValueError('source drift')
            request = spec['request']
            if (not isinstance(request, list) or len(request) > 64
                    or any(not isinstance(x, str) or not x or len(x) > 8192 or '\0' in x for x in request)
                    or len(json.dumps(request)) > MAX_REQUEST):
                raise ValueError('request')
            child_env = build_child_env(selected_execs, utf8_locale=False)
            stdin_bytes = collector_frame(source, request)
            cmd = [sys.executable, '-I', '-c', COLLECTOR_HARNESS]
        else:
            wlen = spec['wrapper_len']
            if not isinstance(wlen, int) or wlen <= 0 or wlen > len(source):
                raise ValueError('wrapper bounds')
            wrapper_bytes = source[:wlen]
            zip_bytes = source[wlen:]
            if hashlib.sha256(wrapper_bytes).hexdigest() != spec['wrapper_sha256']:
                raise ValueError('wrapper drift')
            if hashlib.sha256(zip_bytes).hexdigest() != spec['zip_sha256']:
                raise ValueError('archive drift')
            abz_payload = {
                'wrapper': wrapper_bytes.decode('utf-8', 'strict'),
                'zip_data': base64.b64encode(zip_bytes).decode('ascii'),
                'ansible_module': spec['ansible_module'],
                'module_fqn': spec['module_fqn'],
                'profile': spec['serialization_profile'],
                'params': spec['params'],
            }
            stdin_bytes = json.dumps(abz_payload, separators=(',', ':'), allow_nan=False).encode('utf-8')
            child_env = build_child_env(selected_execs, utf8_locale=True)
            cmd = [sys.executable, '-I', '-X', 'utf8', '-c', ANSIBALLZ_HARNESS]
        child = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=child_env,
                                 start_new_session=True)
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
                            offset += os.write(pipe.fileno(), stdin_bytes[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(stdin_bytes)
                        if offset == len(stdin_bytes):
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
            while True:
                try:
                    os.killpg(child.pid, 0)
                except ProcessLookupError:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                time.sleep(min(remaining, .05))
            response.update(phase='complete', rc=rc, overflow=overflow)
            if overflow:
                response['output_status'] = 'overflow'
            else:
                try:
                    response['stdout'] = output['stdout'].decode('utf-8', errors='strict')
                    response['output_status'] = 'complete'
                except UnicodeDecodeError:
                    response['output_status'] = 'invalid_utf8'
            if rc != 0 or spec['operation'] == 'ansiballz':
                reason = classify_stderr_exception(output['stderr'], output['stdout'] if not overflow else b'')
                if reason is not None and rc != 0:
                    response['error_reason'] = reason
            return response, 0 if rc == 0 else 1
        finally:
            sel.close()
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if child.poll() is None:
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

if __name__ == '__main__':
    try:
        response, rc = run()
    except Exception:
        response, rc = {'schema': 1, 'phase': 'rejected'}, 70
    sys.stdout.write(json.dumps(response, ensure_ascii=True, allow_nan=False, separators=(',', ':')) + '\n')
    sys.stdout.flush()
    sys.exit(rc)
