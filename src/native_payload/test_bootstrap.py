"""Protocol acceptance tests; no SSH, target mutations, or catalog execution."""
import hashlib
import json
import pathlib
import struct
import subprocess
import sys
import unittest

BOOTSTRAP = pathlib.Path(__file__).with_name('bootstrap.py').read_text()
REQ = {'python_min': [3, 8], 'modules': [], 'executables': [], 'paths': []}

def frame(spec, source=b''):
    raw = json.dumps(spec, separators=(',', ':')).encode()
    return b'ESTUSNP1' + struct.pack('!II', len(raw), len(source)) + raw + source

def invoke(raw):
    return subprocess.run([sys.executable, '-I', '-c', BOOTSTRAP], input=raw,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

def collector_frame(source, request=()):
    # The request is a JSON array of typed values; nothing is stringified here.
    raw = json.dumps(list(request), separators=(',', ':')).encode()
    return b'ESTUSCL1' + struct.pack('!II', len(source), len(raw)) + source + raw

class Framing(unittest.TestCase):
    def test_rejects_ambiguous_or_incomplete_frame_before_source(self):
        duplicate = b'{"schema":1,"schema":1}'
        cases = [b'', b'ESTUSNP1' + struct.pack('!II', 262145, 0),
                 b'ESTUSNP1' + struct.pack('!II', len(duplicate), 0) + duplicate,
                 frame({'schema': 1, 'operation': 'nonsense', 'id': 'x', 'requirements': REQ}) + b'x']
        for raw in cases:
            with self.subTest(raw=raw[:24]):
                result = invoke(raw)
                self.assertEqual(result.returncode, 70)
                self.assertEqual(json.loads(result.stdout)['phase'], 'rejected')

@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux boot identity required')
class Execution(unittest.TestCase):
    def execute(self, source, **overrides):
        spec = {'schema': 1, 'operation': 'execute', 'id': 'owned-call', 'requirements': REQ,
                'sha256': hashlib.sha256(source).hexdigest(),
                'request': ['{{ literal }}; \n☃'], 'timeout': 2, 'output_limit': 4096}
        spec.update(overrides)
        result = invoke(frame(spec, source))
        return result.returncode, json.loads(result.stdout)

    def test_isolated_source_and_request_arrive_on_stdin(self):
        source = (
            b'import estus_runtime, json, sys\n'
            b'print(json.dumps({"request": estus_runtime.request(), "argv": sys.argv,'
            b' "isolated": sys.flags.isolated}))\n'
        )
        exit_code, evidence = self.execute(source)
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence['id'], 'owned-call')
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(evidence['rc'], 0)
        self.assertEqual(
            json.loads(evidence['stdout']),
            {'request': ['{{ literal }}; \n☃'], 'argv': ['-'], 'isolated': 1},
        )

    def test_request_values_decode_without_argv_exposure(self):
        source = (
            b'import estus_runtime, json\n'
            b'req = estus_runtime.request()\n'
            b'print(json.dumps([req[0]["unit"], req[1], req[2]]))\n'
        )
        exit_code, evidence = self.execute(
            source,
            request=[{'unit': 'demo.service'}, 'approved', 'plain'],
            argv=None,
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(json.loads(evidence['stdout']), ['demo.service', 'approved', 'plain'])

    def test_request_values_keep_their_json_type(self):
        # A unit, interface or address that looks like JSON must not change type:
        # the frame carries typed values and the harness decodes exactly once.
        source = (
            b'import estus_runtime, json\n'
            b'request = estus_runtime.request()\n'
            b'print(json.dumps([[value, type(value).__name__] for value in request]))\n'
        )
        exit_code, evidence = self.execute(
            source,
            request=['123', 'true', 'null', '1e3', 123, {'unit': 'demo.service'}],
        )
        self.assertEqual(exit_code, 0, evidence)
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(
            json.loads(evidence['stdout']),
            [['123', 'str'], ['true', 'str'], ['null', 'str'], ['1e3', 'str'],
             [123, 'int'], [{'unit': 'demo.service'}, 'dict']],
        )

    def test_request_frame_rejects_non_list_oversize_and_non_finite(self):
        # JSON escapes NUL, so the wire never carries a literal one; collectors
        # reject it in their own bounds checks (check_text).
        for request in ('not-a-list', ['a', 'b'] * 40, [float('inf')]):
            with self.subTest(request=request):
                exit_code, evidence = self.execute(
                    b'raise SystemExit("must not run")', request=request
                )
                self.assertEqual(exit_code, 70)
                self.assertEqual(evidence['phase'], 'rejected')

    def test_collector_harness_rejects_truncation_magic_and_trailing_bytes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'bootstrap_mod', pathlib.Path(__file__).with_name('bootstrap.py')
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = b'print("must not run")\n'
        valid = collector_frame(source)
        for raw in (
            b'ESTUSXX1' + valid[8:],
            valid[:-1],
            valid + b'x',
            b'ESTUSCL1' + struct.pack('!II', 0, 0),
            collector_frame(source, ['ok']) + b'',
        )[:4]:
            with self.subTest(raw=raw[:20]):
                result = subprocess.run(
                    [sys.executable, '-I', '-c', module.COLLECTOR_HARNESS], input=raw,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0, 'malformed collector frame executed')
                self.assertEqual(result.stdout, b'')

    def test_source_digest_drift_rejects_before_execution(self):
        source = b'raise Exception("must not execute")'
        exit_code, evidence = self.execute(source, sha256='0' * 64)
        self.assertEqual(exit_code, 70)
        self.assertEqual(evidence['phase'], 'rejected')
        self.assertNotIn('error_reason', evidence)

    def test_both_streams_are_drained_and_overflow_marked(self):
        source = b'import os; os.write(1,b"x"*100000); os.write(2,b"y"*100000)'
        exit_code, evidence = self.execute(source, output_limit=32)
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(evidence['rc'], 0)
        self.assertTrue(evidence['overflow'])
        self.assertEqual(evidence['output_status'], 'overflow')
        self.assertNotIn('stdout', evidence)
        self.assertNotIn('stderr', evidence)

    def test_multibyte_utf8_cut_at_overflow_limit_preserves_completion(self):
        # Write 31 ASCII bytes + 2-byte UTF-8 sequence (33 bytes total) at output_limit=32.
        source = b'import os,sys; os.write(1, b"a"*31 + b"\\xc3\\xa9"); sys.exit(0)'
        exit_code, evidence = self.execute(source, output_limit=32)
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(evidence['rc'], 0)
        self.assertTrue(evidence['overflow'])
        self.assertEqual(evidence['output_status'], 'overflow')
        self.assertNotIn('stdout', evidence)

    def test_invalid_utf8_preserves_completion_for_zero_and_nonzero_rc(self):
        for rc, expected_exit in ((0, 0), (3, 1)):
            with self.subTest(rc=rc):
                source = f'import os,sys; os.write(1, b"\\xff"); sys.exit({rc})'.encode()
                exit_code, evidence = self.execute(source)
                self.assertEqual(exit_code, expected_exit)
                self.assertEqual(evidence['phase'], 'complete')
                self.assertEqual(evidence['rc'], rc)
                self.assertFalse(evidence['overflow'])
                self.assertEqual(evidence['output_status'], 'invalid_utf8')
                self.assertNotIn('stdout', evidence)

    def test_failed_operation_has_matching_terminal_and_exit(self):
        exit_code, evidence = self.execute(b'import sys; print("{\\"changed\\":true}"); sys.exit(7)')
        self.assertEqual(exit_code, 1)
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(evidence['rc'], 7)
        self.assertEqual(evidence['output_status'], 'complete')

    def test_executable_candidates_select_existing_clear_inherited_env_and_reject_missing(self):
        import os
        sh_candidates = ['/usr/sbin/sh', '/usr/bin/sh', '/sbin/sh', '/bin/sh']
        existing = next((p for p in sh_candidates if os.path.isfile(p) and os.access(p, os.X_OK)), None)
        self.assertIsNotNone(existing, 'expected /bin/sh or /usr/bin/sh in test environment')
        req = {
            'python_min': [3, 8],
            'modules': [],
            'executables': [],
            'paths': [],
            'executable_candidates': {'test-sh': ['/usr/sbin/nonexistent-estus-bin'] + sh_candidates},
        }
        # Execute with poisoned ESTUS_EXEC_* in parent env: child must see only the
        # selected path, and the candidate is re-resolved on this very call.
        source = b'import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith("ESTUS_EXEC_")}))'
        spec = {
            'schema': 1,
            'operation': 'execute',
            'id': 'cand-exec',
            'requirements': req,
            'sha256': hashlib.sha256(source).hexdigest(),
            'request': [],
            'timeout': 5,
            'output_limit': 65536,
        }
        env = dict(os.environ, ESTUS_EXEC_FOREIGN='/tmp/evil', ESTUS_EXEC_TEST_SH='/tmp/override')
        res = subprocess.run([sys.executable, '-I', '-c', BOOTSTRAP], input=frame(spec, source),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10)
        self.assertEqual(res.returncode, 0)
        ev = json.loads(res.stdout)
        self.assertEqual(ev['phase'], 'complete')
        self.assertEqual(json.loads(ev['stdout']), {'ESTUS_EXEC_TEST_SH': existing})

        # Missing candidate refuses the call before the collector runs.
        bad_req = dict(req, executable_candidates={'missing-tool': ['/usr/sbin/definitely-missing-estus']})
        miss = invoke(frame(dict(spec, requirements=bad_req), b'raise SystemExit("must not run")'))
        self.assertEqual(miss.returncode, 70)
        miss_json = json.loads(miss.stdout)
        self.assertEqual(miss_json['phase'], 'rejected')
        self.assertEqual(miss_json['error_reason'], 'dependency_unavailable')

        # Disallowed candidate directory is a policy violation, not a prerequisite.
        evil_req = dict(req, executable_candidates={'evil-tool': ['/tmp/evil']})
        evil = invoke(frame(dict(spec, requirements=evil_req), b'raise SystemExit("must not run")'))
        self.assertEqual(evil.returncode, 70)
        evil_json = json.loads(evil.stdout)
        self.assertEqual(evil_json['phase'], 'rejected')
        self.assertNotIn('error_reason', evil_json)

    def test_missing_module_or_executable_refuses_before_dispatch(self):
        spec = {
            'schema': 1,
            'operation': 'execute',
            'id': 'dep',
            'requirements': dict(REQ, modules=['estus_definitely_absent_module']),
            'sha256': hashlib.sha256(b'raise SystemExit("must not run")').hexdigest(),
            'request': [],
            'timeout': 5,
            'output_limit': 4096,
        }
        missing_module = invoke(frame(spec, b'raise SystemExit("must not run")'))
        self.assertEqual(missing_module.returncode, 70)
        self.assertEqual(json.loads(missing_module.stdout)['phase'], 'rejected')
        self.assertEqual(
            json.loads(missing_module.stdout)['error_reason'], 'dependency_unavailable'
        )

        spec = dict(spec, requirements=dict(REQ, executables=['definitely-missing-estus-util']))
        missing_exec = invoke(frame(spec, b'raise SystemExit("must not run")'))
        self.assertEqual(missing_exec.returncode, 70)
        self.assertEqual(json.loads(missing_exec.stdout)['phase'], 'rejected')
        self.assertEqual(
            json.loads(missing_exec.stdout)['error_reason'], 'dependency_unavailable'
        )

    def test_python_min_rejects_lower_version_before_dispatch(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('bootstrap_mod', pathlib.Path(__file__).with_name('bootstrap.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        req_310 = {'python_min': [3, 10], 'modules': [], 'executables': [], 'paths': []}
        with mock.patch.object(mod.sys, 'version_info', (3, 9, 18, 'final', 0)):
            with self.assertRaises(mod.Prerequisite) as raised:
                mod.check_requirements(req_310)
            self.assertEqual(raised.exception.reason, 'unsupported_platform')
        with mock.patch.object(mod.sys, 'version_info', (3, 10, 0, 'final', 0)):
            self.assertEqual(mod.check_requirements(req_310), {})

    def test_late_exiting_grandchild_is_supervised_then_killed_at_deadline(self):
        import os, tempfile, time
        with tempfile.TemporaryDirectory() as tmp:
            marker = pathlib.Path(tmp) / 'done'
            # Grandchild closes inherited stdio and writes marker after 0.2s, while parent exits immediately with rc=1.
            inner = f"import time; time.sleep(0.2); open({str(marker)!r}, 'w').write('ok')"
            source = (
                f"import subprocess,sys\n"
                f"subprocess.Popen([sys.executable,'-c',{inner!r}],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                f"print('{{\"changed\":null}}')\n"
                f"sys.exit(1)\n"
            ).encode()
            exit_code, evidence = self.execute(source, timeout=3)
            self.assertEqual(exit_code, 1)
            self.assertEqual(evidence['phase'], 'complete')
            self.assertTrue(marker.exists(), 'bootstrap exited before grandchild in process group finished')

            # Grandchild sleeping past outer timeout is killed with the process group at deadline.
            pidfile = pathlib.Path(tmp) / 'child.pid'
            slow_source = (
                f"import subprocess,sys\n"
                f"p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(10)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                f"open({str(pidfile)!r},'w').write(str(p.pid))\n"
                f"sys.exit(1)\n"
            ).encode()
            exit_code, evidence = self.execute(slow_source, timeout=0.3)
            self.assertEqual(exit_code, 124)
            self.assertEqual(evidence['phase'], 'timeout')
            child_pid = int(pidfile.read_text())
            time.sleep(0.05)
            with self.assertRaises(ProcessLookupError):
                os.kill(child_pid, 0)

    def test_failed_collector_classifies_closed_reason_without_leaking_stderr(self):
        secret = 'SUPER_SECRET_TOKEN_VALUE_999'
        for exc, expected in (
            ('PermissionError', 'permission_denied'),
            ('FileNotFoundError', 'target_not_found'),
            ('TimeoutError', 'timeout'),
            ('ValueError', 'policy_violation'),
            ('RuntimeError', 'dependency_unavailable'),
        ):
            with self.subTest(exc=exc):
                source = f'raise {exc}({secret!r})\n'.encode()
                exit_code, evidence = self.execute(source)
                self.assertEqual(exit_code, 1)
                self.assertEqual(evidence['phase'], 'complete')
                self.assertEqual(evidence['error_reason'], expected)
                self.assertNotIn(secret, json.dumps(evidence))
                self.assertNotIn('stderr', evidence)

    def test_estus_runtime_helper_module_provides_bounded_reads_and_subprocess_supervision(self):
        source = (
            b"from __future__ import annotations\n"
            b"import estus_runtime, json, sys\n"
            b"bid = estus_runtime.boot_id()\n"
            b"txt = estus_runtime.check_text('ok', 16)\n"
            b"missing = estus_runtime.read_bytes('/nonexistent-estus-runtime-path', 64, optional=True)\n"
            b"try:\n"
            b"    estus_runtime.run_bounded([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)\n"
            b"    timed_out = False\n"
            b"except TimeoutError:\n"
            b"    timed_out = True\n"
            b"print(json.dumps({'boot_len': len(bid), 'txt': txt, 'missing': missing, 'timed_out': timed_out}))\n"
        )
        exit_code, evidence = self.execute(source, timeout=3)
        self.assertEqual(exit_code, 0)
        out = json.loads(evidence['stdout'])
        self.assertEqual(out['boot_len'], 36)
        self.assertEqual(out['txt'], 'ok')
        self.assertIsNone(out['missing'])
        self.assertTrue(out['timed_out'])

    def test_run_bounded_fsize_scales_with_max_bytes(self):
        source = (
            b"import estus_runtime, json, sys\n"
            b"res = estus_runtime.run_bounded([sys.executable, '-c', 'import sys; sys.stdout.write(\"x\" * 600000)'], max_bytes=1048576)\n"
            b"print(json.dumps({'rc': res['returncode'], 'timed_out': res['timed_out'], 'len': len(res['stdout'])}))\n"
        )
        exit_code, evidence = self.execute(source, timeout=10)
        self.assertEqual(exit_code, 0)
        out = json.loads(evidence['stdout'])
        self.assertEqual(out['rc'], 0)
        self.assertFalse(out['timed_out'])
        self.assertEqual(out['len'], 600000)

    def test_allowlist_helper_denies_absent_empty_non_list_and_allows_explicit_wildcard(self):
        source = (
            b"import estus_runtime, json\n"
            b"cases = [\n"
            b"    estus_runtime.allowed('demo.service', ['demo.service']),\n"
            b"    estus_runtime.allowed('other.service', ['demo.service']),\n"
            b"    estus_runtime.allowed('demo.service', ['*']),\n"
            b"    estus_runtime.allowed('demo.service', None),\n"
            b"    estus_runtime.allowed('demo.service', []),\n"
            b"    estus_runtime.allowed('demo.service', ''),\n"
            b"    estus_runtime.allowed('demo.service', 'demo.service'),\n"
            b"    estus_runtime.allowed('demo.service', {'demo.service': True}),\n"
            b"    estus_runtime.allowed('', ['*']),\n"
            b"    estus_runtime.allowed(None, ['*']),\n"
            b"]\n"
            b"print(json.dumps(cases))\n"
        )
        exit_code, evidence = self.execute(source)
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(evidence['stdout']),
            [True, False, True, False, False, False, False, False, False, False],
        )

    def test_run_bounded_classifies_failures_timeouts_and_accepted_statuses(self):
        source = (
            b"import estus_runtime, json, sys\n"
            b"def code(fn):\n"
            b"    try:\n"
            b"        return fn()\n"
            b"    except Exception as error:\n"
            b"        return type(error).__name__\n"
            b"ok = estus_runtime.run_bounded([sys.executable, '-c', 'print(\"fine\")'])\n"
            b"tolerant = estus_runtime.run_bounded(\n"
            b"    [sys.executable, '-c', 'import sys; sys.stderr.write(\"noise\"); sys.exit(3)'],\n"
            b"    accepted=(0, 3))\n"
            b"print(json.dumps({\n"
            b"    'stdout': ok['stdout'].strip(),\n"
            b"    'rc': tolerant['returncode'],\n"
            b"    'stderr': tolerant['stderr'],\n"
            b"    'rejected': code(lambda: estus_runtime.run_bounded([sys.executable, '-c', 'import sys; sys.exit(4)'])),\n"
            b"    'timeout': code(lambda: estus_runtime.run_bounded([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)),\n"
            b"    'oversize': code(lambda: estus_runtime.run_bounded([sys.executable, '-c', 'print(\"y\" * 5000)'], max_bytes=64)),\n"
            b"    'bad_utf8': code(lambda: estus_runtime.run_bounded([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(b\"\\\\xff\")'])),\n"
            b"    'empty_argv': code(lambda: estus_runtime.run_bounded([])),\n"
            b"    'nul_argv': code(lambda: estus_runtime.run_bounded(['/bin/sh', 'a' + chr(0) + 'b'])),\n"
            b"    'empty_program': code(lambda: estus_runtime.run_bounded(['', 'x'])),\n"
            b"    'empty_arg': estus_runtime.run_bounded([sys.executable, '-c', 'import sys; print(repr(sys.argv[1]))', ''])['stdout'].strip(),\n"
            b"}))\n"
        )
        exit_code, evidence = self.execute(source, timeout=10)
        self.assertEqual(exit_code, 0)
        out = json.loads(evidence['stdout'])
        self.assertEqual(out['stdout'], 'fine')
        self.assertEqual(out['rc'], 3)
        self.assertEqual(out['stderr'], 'noise')
        self.assertEqual(out['rejected'], 'CommandFailed')
        self.assertEqual(out['timeout'], 'TimeoutError')
        self.assertEqual(out['oversize'], 'ValueError')
        self.assertEqual(out['bad_utf8'], 'UnicodeDecodeError')
        self.assertEqual(out['empty_argv'], 'ValueError')
        self.assertEqual(out['nul_argv'], 'ValueError')
        self.assertEqual(out['empty_program'], 'ValueError')
        self.assertEqual(out['empty_arg'], "''")

    def test_run_or_exit_publishes_classified_error_document(self):
        source = (
            b"import estus_runtime, sys\n"
            b"estus_runtime.run_or_exit([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.1)\n"
        )
        exit_code, evidence = self.execute(source, timeout=10)
        self.assertEqual(exit_code, 1)
        self.assertEqual(evidence['rc'], 1)
        self.assertEqual(json.loads(evidence['stdout']), {'estus_error': {'code': 'timeout'}})

    def test_collector_allowlist_fails_closed_and_wildcard_is_explicit(self):
        # The shipped systemd unit collector is the regression the audit found:
        # an absent allowed_units must deny instead of permitting any unit.
        source = pathlib.Path(__file__).parents[2] / 'catalog/payloads/change_systemd_unit/collector.py'
        probe = (
            b"import importlib.util, json, sys, types\n"
            b"bootstrap = types.ModuleType('b')\n"
            b"exec(compile(open(sys.argv[2]).read(), 'b', 'exec'), bootstrap.__dict__)\n"
            b"runtime = {'types': types}\n"
            b"exec(compile(bootstrap.COLLECTOR_RUNTIME, 'r', 'exec'), runtime)\n"
            b"sys.modules['estus_runtime'] = runtime['_make_runtime']([])\n"
            b"spec = importlib.util.spec_from_file_location('c', sys.argv[1])\n"
            b"module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)\n"
            b"check = module.unit_allowed\n"
            b"print(json.dumps({\n"
            b"  'listed': check('estus-fixture.service', ['estus-fixture.service']),\n"
            b"  'unlisted': check('ssh.service', ['estus-fixture.service']),\n"
            b"  'wildcard': check('ssh.service', ['*']),\n"
            b"  'absent': check('ssh.service', None),\n"
            b"  'empty': check('ssh.service', []),\n"
            b"  'non_list': check('ssh.service', 'ssh.service'),\n"
            b"  'malformed_unit': check('bad unit!', ['*']),\n"
            b"}))\n"
        )
        result = subprocess.run(
            [sys.executable, '-I', '-B', '-c', probe, str(source),
             str(pathlib.Path(__file__).with_name('bootstrap.py'))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            json.loads(result.stdout),
            {'listed': True, 'unlisted': False, 'wildcard': True, 'absent': False,
             'empty': False, 'non_list': False, 'malformed_unit': False},
        )

    def test_ansiballz_execution_cleans_tmpdir_and_classifies_missing_deps(self):
        import glob, os, tempfile
        wrapper = (
            b"import json, os, sys\n"
            b"def _ansiballz_main(zip_data, ansible_module, module_fqn, params, profile, date_time, extensions, rlimit_nofile):\n"
            b"    args = json.loads(params)['ANSIBLE_MODULE_ARGS']\n"
            b"    td = args['_ansible_tmpdir']\n"
            b"    assert os.path.isdir(td)\n"
            b"    if args.get('fail_dep'):\n"
            b"        print(json.dumps({'failed': True, 'msg': 'Could not import python modules: python3-apt'}))\n"
            b"        sys.exit(1)\n"
            b"    print(json.dumps({'changed': False, 'echo': args.get('val'), 'check': args['_ansible_check_mode']}))\n"
        )
        zip_bytes = b'PK\x05\x06' + b'\x00' * 18
        combined = wrapper + zip_bytes
        spec = {
            'schema': 1,
            'operation': 'ansiballz',
            'id': 'abz-1',
            'requirements': REQ,
            'wrapper_len': len(wrapper),
            'wrapper_sha256': hashlib.sha256(wrapper).hexdigest(),
            'zip_sha256': hashlib.sha256(zip_bytes).hexdigest(),
            'ansible_module': 'stat',
            'module_fqn': 'ansible.modules.stat',
            'serialization_profile': 'legacy',
            'params': {'ANSIBLE_MODULE_ARGS': {'val': 'hello', '_ansible_check_mode': True}},
            'timeout': 5,
            'output_limit': 16384,
        }
        res = invoke(frame(spec, combined))
        self.assertEqual(res.returncode, 0)
        ev = json.loads(res.stdout)
        self.assertEqual(ev['phase'], 'complete')
        self.assertEqual(json.loads(ev['stdout']), {'changed': False, 'echo': 'hello', 'check': True})
        self.assertEqual(glob.glob(os.path.join(tempfile.gettempdir(), 'estus_abz_*')), [])

        spec['id'] = 'abz-dep'
        spec['params'] = {'ANSIBLE_MODULE_ARGS': {'fail_dep': True, '_ansible_check_mode': False}}
        res_fail = invoke(frame(spec, combined))
        self.assertEqual(res_fail.returncode, 1)
        ev_fail = json.loads(res_fail.stdout)
        self.assertEqual(ev_fail.get('error_reason'), 'dependency_unavailable')

class PackagePrestate(unittest.TestCase):
    def test_apk_database_changes_invalidate_prestate(self):
        import importlib.util
        import tempfile
        from unittest import mock

        spec = importlib.util.spec_from_file_location('prestate_mod', pathlib.Path(__file__).with_name('prestate.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            database = pathlib.Path(directory) / 'installed'
            database.write_text('P:example\nV:1\n')
            real_canonical_file = module.canonical_file
            with mock.patch.object(module, 'canonical_file', side_effect=lambda _path, limit: real_canonical_file(database, limit)):
                before = module.observe_apk({'name': ['example']})
                database.write_text('P:example\nV:2\n')
                after = module.observe_apk({'name': ['example']})
            self.assertEqual(before['backend'], 'apk')
            self.assertNotEqual(before['database']['sha256'], after['database']['sha256'])

    def test_canonical_file_rejects_symlinks_with_value_error(self):
        import importlib.util
        import tempfile
        from unittest import mock

        spec = importlib.util.spec_from_file_location('prestate_mod', pathlib.Path(__file__).with_name('prestate.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'target'
            target.write_bytes(b'payload')
            link = pathlib.Path(directory) / 'link'
            link.symlink_to(target)
            state = module.canonical_file(str(target))
            self.assertTrue(state['exists'])
            self.assertEqual(state['size'], 7)
            with self.assertRaises(ValueError):
                module.canonical_file(str(link))

    def test_observe_sysctl_accepts_null_sysctl_file(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location('prestate_mod', pathlib.Path(__file__).with_name('prestate.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.observe_sysctl({'name': 'kernel.ostype', 'sysctl_file': None})
        self.assertIsNone(result['sysctl_file'])
        self.assertIsNone(result['file'])
        self.assertIn('proc_sys', result)

if __name__ == '__main__':
    unittest.main()
