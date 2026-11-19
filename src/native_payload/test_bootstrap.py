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

class Framing(unittest.TestCase):
    def test_rejects_ambiguous_or_incomplete_frame_before_source(self):
        duplicate = b'{"schema":1,"schema":1}'
        cases = [b'', b'ESTUSNP1' + struct.pack('!II', 262145, 0),
                 b'ESTUSNP1' + struct.pack('!II', len(duplicate), 0) + duplicate,
                 frame({'schema': 1, 'operation': 'discover', 'id': 'x', 'requirements': REQ}) + b'x']
        for raw in cases:
            with self.subTest(raw=raw[:24]):
                result = invoke(raw)
                self.assertEqual(result.returncode, 70)
                self.assertEqual(json.loads(result.stdout)['phase'], 'rejected')

@unittest.skipUnless(sys.platform.startswith('linux'), 'Linux boot identity required')
class Execution(unittest.TestCase):
    def setUp(self):
        result = invoke(frame({'schema': 1, 'operation': 'discover', 'id': 'probe', 'requirements': REQ}))
        self.assertEqual(result.returncode, 0)
        self.identity = json.loads(result.stdout)['identity']

    def execute(self, source, **overrides):
        spec = {'schema': 1, 'operation': 'execute', 'id': 'owned-call', 'requirements': REQ,
                'identity': self.identity, 'sha256': hashlib.sha256(source).hexdigest(),
                'argv': ['{{ literal }}; \n☃'], 'timeout': 2, 'output_limit': 4096}
        spec.update(overrides)
        result = invoke(frame(spec, source))
        return result.returncode, json.loads(result.stdout)

    def test_isolated_stdin_source_and_literal_argv(self):
        source = b'import json,sys; print(json.dumps({"arg":sys.argv[1],"isolated":sys.flags.isolated}))'
        exit_code, evidence = self.execute(source)
        self.assertEqual(exit_code, 0)
        self.assertEqual(evidence['id'], 'owned-call')
        self.assertEqual(evidence['phase'], 'complete')
        self.assertEqual(evidence['rc'], 0)
        self.assertEqual(json.loads(evidence['stdout']), {'arg': '{{ literal }}; \n☃', 'isolated': 1})

    def test_digest_and_identity_drift_reject_before_source(self):
        source = b'raise Exception("must not execute")'
        for override in ({'sha256': '0' * 64}, {'identity': dict(self.identity, boot='stale-boot')}):
            exit_code, evidence = self.execute(source, **override)
            self.assertEqual(exit_code, 70)
            self.assertEqual(evidence['phase'], 'rejected')

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
        disc = invoke(frame({'schema': 1, 'operation': 'discover', 'id': 'cand', 'requirements': req}))
        self.assertEqual(disc.returncode, 0)
        disc_json = json.loads(disc.stdout)
        self.assertEqual(disc_json['phase'], 'discovered')
        ident = disc_json['identity']
        self.assertEqual(ident['executable_candidates']['test-sh'][0], os.path.realpath(existing))

        # Execute with poisoned ESTUS_EXEC_* in parent env: child must see only selected path.
        source = b'import json,os; print(json.dumps({k:v for k,v in os.environ.items() if k.startswith("ESTUS_EXEC_")}))'
        spec = {
            'schema': 1,
            'operation': 'execute',
            'id': 'cand-exec',
            'requirements': req,
            'identity': ident,
            'sha256': hashlib.sha256(source).hexdigest(),
            'argv': [],
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

        # Missing candidate fails discovery before dispatch.
        bad_req = dict(req, executable_candidates={'missing-tool': ['/usr/sbin/definitely-missing-estus']})
        miss = invoke(frame({'schema': 1, 'operation': 'discover', 'id': 'miss', 'requirements': bad_req}))
        self.assertEqual(miss.returncode, 70)
        self.assertEqual(json.loads(miss.stdout)['phase'], 'rejected')

        # Disallowed candidate directory fails discovery before dispatch.
        evil_req = dict(req, executable_candidates={'evil-tool': ['/tmp/evil']})
        evil = invoke(frame({'schema': 1, 'operation': 'discover', 'id': 'evil', 'requirements': evil_req}))
        self.assertEqual(evil.returncode, 70)
        self.assertEqual(json.loads(evil.stdout)['phase'], 'rejected')

    def test_python_min_rejects_lower_version_before_dispatch(self):
        import importlib.util
        from unittest import mock
        spec = importlib.util.spec_from_file_location('bootstrap_mod', pathlib.Path(__file__).with_name('bootstrap.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        req_310 = {'python_min': [3, 10], 'modules': [], 'executables': [], 'paths': []}
        with mock.patch.object(mod.sys, 'version_info', (3, 9, 18, 'final', 0)):
            with self.assertRaisesRegex(ValueError, 'unsupported interpreter'):
                mod.identity(req_310)
        with mock.patch.object(mod.sys, 'version_info', (3, 10, 0, 'final', 0)):
            ident = mod.identity(req_310)
            self.assertEqual(ident['version'], [3, 10, 0])

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
if __name__ == '__main__':
    unittest.main()
