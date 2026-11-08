"""Reject occupied output paths before input access and reject disabled evidence checks."""
from contextlib import redirect_stderr
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import check_recompiled_numeric as numeric
import verify_colorspace_ui as ui


class ResearchGuardTests(unittest.TestCase):
    def test_dangling_output_link_rejected_before_inputs_or_build(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'absent-target.json'
            output = Path(directory)/'report.json'
            try:
                output.symlink_to(target)
            except OSError as error:
                self.skipTest(f'Symlink unavailable: {error}')
            self.assertFalse(output.exists())
            self.assertTrue(os.path.lexists(output))
            argv = ['check', 'missing.bin', 'missing.elf', '--zig', 'missing.exe',
                    '--work-dir', str(ROOT/'.private/recompiled-numeric/unused-guard-test'), '--output', str(output)]
            with patch.object(sys, 'argv', argv), patch.object(numeric, 'verify') as verify, redirect_stderr(io.StringIO()) as errors:
                with self.assertRaises(SystemExit) as caught:
                    numeric.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('output must not exist', errors.getvalue())
            verify.assert_not_called()
            self.assertFalse(target.exists())
            self.assertTrue(output.is_symlink())

    def test_colorspace_metadata_rejects_nonhex_digest_and_missing_function(self):
        original = json.loads((ROOT/'analysis/colorspace-ui.json').read_text(encoding='utf-8'))
        for kind in ('nonhex', 'missing'):
            changed = deepcopy(original)
            if kind == 'nonhex':
                changed['selected_functions'][0]['sha256'] = 'z'*64
            else:
                changed['selected_functions'].pop()
            with self.subTest(kind=kind), patch.object(ui, 'read', return_value=changed):
                with self.assertRaises(AssertionError):
                    ui.verify()

    def test_other_recent_replay_clis_reject_dangling_output_before_input(self):
        scripts = ('check_burn_storage.py', 'check_lens_readiness.py', 'check_colorspace_ui.py',
                   'check_burn_input.py', 'check_lens_policy.py')
        with tempfile.TemporaryDirectory() as directory:
            target, output = Path(directory)/'absent-target.json', Path(directory)/'report.json'
            try:
                output.symlink_to(target)
            except OSError as error:
                self.skipTest(f'Symlink unavailable: {error}')
            for script in scripts:
                with self.subTest(script=script):
                    result = subprocess.run([sys.executable, str(ROOT/'tools'/script), 'missing-input',
                                             '--output', str(output)], cwd=ROOT, capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('output must not exist', result.stderr)
                    self.assertFalse(target.exists())
                    self.assertTrue(output.is_symlink())

    def test_colorspace_metadata_rejects_optimized_python(self):
        result = subprocess.run([sys.executable, '-O', str(ROOT/'tools/verify_colorspace_ui.py')],
                                cwd=ROOT, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Validation requires assertions', result.stderr)
        self.assertNotIn('metadata: PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
