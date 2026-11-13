"""Verify NAND replay evidence and protect input and output files."""
from contextlib import redirect_stderr
from copy import deepcopy
from hashlib import sha256
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
SCRIPT = ROOT / 'tools/check_nand_headers.py'
sys.path.insert(0, str(SCRIPT.parent))
import check_nand_headers as nand


class NandHeaderTests(unittest.TestCase):
    def test_canonical_report_and_case_tampering(self):
        report = json.loads((ROOT / 'analysis/nand-header-checks.json').read_text(encoding='utf-8'))
        nand.validate_report(report)
        mutations = (
            (('parser', 'cases', 0, 'result'), 0),
            (('native_open_entries', 0, 'initial_c18'), 0),
            (('header_redirect', 1, 'aligned_redirect'), 0x123),
            (('source', 'selected_ranges', 0, 'byte_equal'), False),
        )
        for path, value in mutations:
            with self.subTest(path=path):
                changed = deepcopy(report)
                item = changed
                for key in path[:-1]:
                    item = item[key]
                item[path[-1]] = value
                with self.assertRaises(AssertionError):
                    nand.validate_report(changed)

    def test_firmware_and_elf_sha_checked_before_engine_import(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'analysis.elf'
            firmware = b'synthetic firmware'
            with patch.dict(sys.modules, {'angr': None}):
                with self.assertRaisesRegex(ValueError, '(?i)firmware'):
                    nand.replay(firmware, elf)
                elf.write_bytes(b'synthetic ELF')
                with patch.object(nand, 'SHA', sha256(firmware).hexdigest()):
                    with self.assertRaisesRegex(ValueError, '(?i)ELF'):
                        nand.replay(firmware, elf)

    def test_optimized_cli_refuses_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'report.json'
            result = subprocess.run(
                [sys.executable, '-B', '-O', str(SCRIPT), 'missing.bin', 'missing.elf',
                 '--output', str(output)],
                cwd=ROOT, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('replay requires assertions', result.stderr)
            self.assertFalse(output.exists())

    def assert_occupied_output_rejected(self, output, firmware, elf):
        argv = [str(SCRIPT), str(firmware), str(elf), '--output', str(output)]
        with patch.object(sys, 'argv', argv), patch.object(nand, 'replay') as replay:
            with redirect_stderr(io.StringIO()) as errors, self.assertRaises(SystemExit) as caught:
                nand.main()
            replay.assert_not_called()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('output must not exist', errors.getvalue())

    def test_existing_output_and_input_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware, elf, existing = (Path(directory) / name for name in ('input.bin', 'input.elf', 'existing.json'))
            originals = {firmware: b'firmware', elf: b'ELF', existing: b'existing report'}
            for path, content in originals.items():
                path.write_bytes(content)
            self.assert_occupied_output_rejected(
                existing, Path(directory) / 'missing.bin', Path(directory) / 'missing.elf',
            )
            for output in (firmware, elf):
                with self.subTest(output=output.name):
                    self.assert_occupied_output_rejected(output, firmware, elf)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_hardlink_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware, elf, output = (Path(directory) / name for name in ('input.bin', 'missing.elf', 'alias.json'))
            firmware.write_bytes(b'firmware')
            os.link(firmware, output)
            self.assert_occupied_output_rejected(output, firmware, elf)
            self.assertTrue(output.samefile(firmware))
            self.assertEqual(firmware.read_bytes(), b'firmware')

    def test_live_and_dangling_symlink_outputs_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware, elf, target = (Path(directory) / name for name in ('input.bin', 'missing.elf', 'absent.json'))
            firmware.write_bytes(b'firmware')
            for label, link_target in (('live', firmware), ('dangling', target)):
                with self.subTest(label=label):
                    output = Path(directory) / (label + '.json')
                    try:
                        output.symlink_to(link_target)
                    except OSError as error:
                        self.skipTest(f'Symlink unavailable: {error}')
                    stored_target = output.readlink()
                    self.assert_occupied_output_rejected(output, firmware, elf)
                    self.assertEqual(output.readlink(), stored_target)
            self.assertEqual(firmware.read_bytes(), b'firmware')
            self.assertFalse(target.exists())

    def test_exclusive_output_creation_preserves_file_created_during_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            firmware, elf, output = (Path(directory) / name for name in ('input.bin', 'input.elf', 'report.json'))
            firmware.write_bytes(b'firmware')
            elf.write_bytes(b'ELF')

            def replay_with_competing_writer(raw, elf_path):
                self.assertEqual(raw, b'firmware')
                self.assertEqual(elf_path, elf)
                output.write_bytes(b'competing report')
                return {}

            argv = [str(SCRIPT), str(firmware), str(elf), '--output', str(output)]
            with (
                patch.object(sys, 'argv', argv),
                patch.object(nand, 'replay', side_effect=replay_with_competing_writer),
                patch.object(nand, 'REPORT_SHA256', sha256(b'{}').hexdigest()),
                redirect_stderr(io.StringIO()) as errors,
                self.assertRaises(SystemExit) as caught,
            ):
                nand.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('output appeared while replaying', errors.getvalue())
            self.assertEqual(output.read_bytes(), b'competing report')


if __name__ == '__main__':
    unittest.main()
