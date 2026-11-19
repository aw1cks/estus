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

if __name__ == '__main__':
    unittest.main()
