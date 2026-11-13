"""Verify context replay evidence and guard input, source, and output files."""
from contextlib import redirect_stderr
from copy import deepcopy
from hashlib import sha256
import importlib
from importlib.machinery import PathFinder
import io
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/check_nand_context.py'
sys.path.insert(0, str(SCRIPT.parent))
import check_nand_context as nand


class NandContextTests(unittest.TestCase):
    def test_canonical_report_and_case_tampering(self):
        report = json.loads((ROOT / 'analysis/nand-context-checks.json').read_text(encoding='utf-8'))
        nand.validate_report(report)
        for key, value in (
            (('context', 'final', 'next_read_address'), '0x224'),
            (('discovery', 'cases', 1, 'final', 'record_c88'), 0x79),
            (('source', 'package_template', 'actual_installed_media'), True),
            (('analysis_elf_sha256',), '0' * 64),
            (('input_sha256',), '0' * 64),
        ):
            with self.subTest(path=key):
                changed = deepcopy(report)
                item = changed
                for index in key[:-1]:
                    item = item[index]
                item[key[-1]] = value
                with self.assertRaises(AssertionError):
                    nand.validate_report(changed)

    def test_firmware_and_elf_sha_checked_before_dependencies_and_engine(self):
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'analysis.elf'
            firmware = b'synthetic firmware'
            with (
                patch.dict(sys.modules, {'angr': None}),
                patch.object(nand, 'pinned_dependencies') as dependencies,
            ):
                with self.assertRaisesRegex(ValueError, '(?i)firmware'):
                    nand.replay(firmware, elf)
                elf.write_bytes(b'synthetic ELF')
                with patch.object(nand, 'SHA', sha256(firmware).hexdigest()):
                    with self.assertRaisesRegex(ValueError, '(?i)ELF'):
                        nand.replay(firmware, elf)
                dependencies.assert_not_called()

    def test_all_dependency_pins_pass_before_any_dependency_executes(self):
        names = tuple(nand.SOURCE_PINS)
        self.assertEqual(len(names), 11)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / 'executed'
            verified_source = (
                f'from pathlib import Path\nPath({str(marker)!r}).touch()\n'
            ).encode('utf-8')
            pins = dict.fromkeys(names, sha256(verified_source).hexdigest())
            for name in names:
                (root / (name + '.py')).write_bytes(verified_source)
            (root / (names[-1] + '.py')).write_bytes(verified_source + b'# changed\n')
            firmware, elf = b'firmware', root / 'input.elf'
            elf.write_bytes(b'ELF')
            dependencies = nand.pinned_dependencies
            with (
                patch.object(nand, 'SHA', sha256(firmware).hexdigest()),
                patch.object(nand, 'ELF_SHA256', sha256(b'ELF').hexdigest()),
                patch.object(nand, 'SOURCE_PINS', pins),
                patch.object(nand, 'pinned_dependencies', side_effect=lambda: dependencies(root)),
                patch.dict(sys.modules, {'angr': None}),
                self.assertRaisesRegex(ValueError, names[-1]),
            ):
                nand.replay(firmware, elf)
            self.assertFalse(marker.exists())

    def test_verified_source_snapshot_ignores_matching_pyc_and_preloaded_module(self):
        name = 'nand_context_loader_fixture'
        mutator = 'nand_context_loader_mutator'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / (name + '.py')
            verified = b'VALUE = "source"\n'
            untrusted = b'VALUE = "cached"\n'
            source.write_bytes(untrusted)
            timestamps = source.stat()
            cache = Path(py_compile.compile(
                str(source), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP,
            ))
            cached_bytes = cache.read_bytes()
            source.write_bytes(verified)
            os.utime(source, ns=(timestamps.st_atime_ns, timestamps.st_mtime_ns))
            disk_loader = PathFinder.find_spec(name, [str(root)]).loader
            self.assertIn('cached', disk_loader.get_code(name).co_consts)

            # The first verified dependency changes the second file after both were pinned.
            later = b'VALUE = "edited"\n'
            mutation = (
                'import os\n'
                'from pathlib import Path\n'
                f'source = Path({str(source)!r})\n'
                'timestamps = source.stat()\n'
                f'source.write_bytes({later!r})\n'
                'os.utime(source, ns=(timestamps.st_atime_ns, timestamps.st_mtime_ns))\n'
            ).encode('utf-8')
            (root / (mutator + '.py')).write_bytes(mutation)
            pins = {mutator: sha256(mutation).hexdigest(), name: sha256(verified).hexdigest()}
            preloaded = ModuleType(name)
            preloaded.VALUE = 'preloaded'
            with patch.dict(sys.modules, {name: preloaded}), patch.object(nand, 'SOURCE_PINS', pins):
                with nand.pinned_dependencies(root):
                    loaded = importlib.import_module(name)
                    self.assertIsNot(loaded, preloaded)
                    self.assertEqual(loaded.VALUE, 'source')
                self.assertIs(sys.modules[name], preloaded)
                self.assertNotIn(mutator, sys.modules)
            self.assertEqual(source.read_bytes(), later)
            self.assertIn('cached', disk_loader.get_code(name).co_consts)
            self.assertEqual(cache.read_bytes(), cached_bytes)

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
        with (
            patch.object(sys, 'argv', argv),
            patch.object(nand, 'replay') as replay,
            redirect_stderr(io.StringIO()) as errors,
            self.assertRaises(SystemExit) as caught,
        ):
            nand.main()
        replay.assert_not_called()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('output must not exist', errors.getvalue())

    def test_existing_output_and_input_paths_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware, elf, existing = (root / name for name in ('input.bin', 'input.elf', 'existing.json'))
            originals = {firmware: b'firmware', elf: b'ELF', existing: b'existing report'}
            for path, content in originals.items():
                path.write_bytes(content)
            self.assert_occupied_output_rejected(existing, root / 'missing.bin', root / 'missing.elf')
            for output in (firmware, elf):
                with self.subTest(output=output.name):
                    self.assert_occupied_output_rejected(output, firmware, elf)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)

    def test_hardlink_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware, output = root / 'input.bin', root / 'alias.json'
            firmware.write_bytes(b'firmware')
            os.link(firmware, output)
            self.assert_occupied_output_rejected(output, firmware, root / 'missing.elf')
            self.assertTrue(output.samefile(firmware))
            self.assertEqual(firmware.read_bytes(), b'firmware')

    def test_live_and_dangling_symlink_outputs_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware, absent = root / 'input.bin', root / 'absent.json'
            firmware.write_bytes(b'firmware')
            for label, target in (('live', firmware), ('dangling', absent)):
                with self.subTest(label=label):
                    output = root / (label + '.json')
                    try:
                        output.symlink_to(target)
                    except OSError as error:
                        self.skipTest(f'Symlink unavailable: {error}')
                    original_target = output.readlink()
                    self.assert_occupied_output_rejected(output, firmware, root / 'missing.elf')
                    self.assertEqual(output.readlink(), original_target)
            self.assertEqual(firmware.read_bytes(), b'firmware')
            self.assertFalse(absent.exists())

    def test_exclusive_creation_preserves_file_created_during_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            firmware, elf, output = (root / name for name in ('input.bin', 'input.elf', 'report.json'))
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
                patch.object(nand, 'validate_report'),
                redirect_stderr(io.StringIO()) as errors,
                self.assertRaises(SystemExit) as caught,
            ):
                nand.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertIn('output appeared while replaying', errors.getvalue())
            self.assertEqual(output.read_bytes(), b'competing report')


if __name__ == '__main__':
    unittest.main()
