"""Synthetic trust-boundary and frozen-observation tests; no DCP or III checkout."""
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
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import check_q7_dcp_structure as dcp


class DcpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".q7-dcp-test-", dir=ROOT)
        self.root = Path(self.temp.name).resolve()
        self.assertTrue(self.root.is_relative_to(ROOT.resolve()))
        self.addCleanup(self.temp.cleanup)

    def test_bounded_descriptor_capture(self):
        path = self.root / "sample"
        path.write_bytes(b"abc")
        self.assertEqual(dcp.capture(path, 3), b"abc")
        with self.assertRaises(ValueError):
            dcp.capture(path, 2)
        with patch.object(dcp, "fstat", return_value=SimpleNamespace(st_mode=0, st_size=3)):
            with self.assertRaises(ValueError):
                dcp.capture(path, 3)
        # A descriptor reporting an earlier size must not hide growth in the bounded read.
        real = os.stat(path)
        with patch.object(dcp, "fstat", return_value=SimpleNamespace(st_mode=real.st_mode, st_size=2)):
            with self.assertRaises(ValueError):
                dcp.capture(path, 3)
        path.write_bytes(b"abcd")
        with patch.object(dcp, "fstat", return_value=SimpleNamespace(st_mode=real.st_mode, st_size=3)):
            with self.assertRaises(ValueError):
                dcp.capture(path, 3)

    def test_hash_and_json_use_one_captured_buffer(self):
        path = self.root / "source.json"
        before = b'{"AsShot":[5100,-17]}\r\n'
        path.write_bytes(before)
        calls = []
        class ReplacingPath:
            name = "source.json"
            def open(self, mode):
                calls.append(("open", mode))
                stream = path.open(mode)
                class Reader:
                    def __enter__(self): return self
                    def __exit__(self, *args): stream.close()
                    def fileno(self): return stream.fileno()
                    def read(self, size):
                        calls.append(("read", size))
                        data = stream.read(size)
                        path.write_bytes(b'{"AsShot":[9999,99]}')
                        return data
                return Reader()
        parsed, hashes = dcp.captured_json(ReplacingPath(), sha256(before.replace(b"\r\n", b"\n")).hexdigest())
        self.assertEqual(parsed, {"AsShot": [5100,-17]})
        self.assertEqual(hashes["sha256"], sha256(before).hexdigest())
        self.assertNotEqual(hashes["sha256"], hashes["sha256_lf"])
        self.assertEqual(calls, [("open", "rb"), ("read", dcp.CAP + 1)])

    def test_wrong_hash_rejected_before_parsing(self):
        path = self.root / "invalid.json"
        path.write_bytes(b"not json")
        with patch.object(dcp.json, "loads") as loads:
            with self.assertRaises(ValueError):
                dcp.captured_json(path, "0"*64)
            loads.assert_not_called()

    def test_complete_frozen_observations(self):
        record = dcp.load_record()
        original = dcp.validate_report(record)
        self.assertEqual(dcp.canonical(original), dcp.OBSERVATIONS_SHA)
        for key in original:
            changed = deepcopy(record)
            changed.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                dcp.validate_report(changed)
        changed = deepcopy(record)
        changed["profiles"]["adobe"]["tables"]["ProfileLookTableData"]["value_scale"]["min"] = .5
        with self.assertRaises(ValueError): dcp.validate_report(changed)
        changed = deepcopy(record)
        changed["_publication"]["research_code_sha256"] = "0"*64
        with self.assertRaises(ValueError): dcp.validate_report(changed)

    def test_environment_normalization_is_narrow(self):
        frozen = dcp.load_record()
        actual = deepcopy(dcp.validate_report(frozen))
        actual.pop("inputs_unchanged_after_analysis")
        actual["profiles"]["adobe"]["file"] = "user-renamed.dcp"
        for source in actual["source_reports"].values(): source["sha256"] = "0"*64
        dcp.compare_observations(actual, frozen)
        actual["historical_as_shot_q7"]["profile_temperature_tint"] = [9999,99]
        with self.assertRaises(ValueError): dcp.compare_observations(actual, frozen)

    def test_tone_metrics_boundaries(self):
        self.assertIsNone(dcp.tone_metrics(None)["identity_max_abs_at_knots"])
        self.assertEqual(dcp.tone_metrics([0,0,.5,.75,1,1])["identity_max_abs_at_knots"], .25)
        self.assertFalse(dcp.tone_metrics([0,0,0,.5,1,1])["strict_x"])
        self.assertFalse(dcp.tone_metrics([0,0,.5,.8,1,.7])["nondecreasing_y"])
        self.assertFalse(dcp.tone_metrics([0,0,1,1.1])["domain_0_1"])
        for values in ([0,0,1], [0,0,1,float("nan")], [0,0,1,float("inf")]):
            with self.assertRaises(ValueError): dcp.tone_metrics(values)

    def dangling(self):
        link, target = self.root / "result.json", self.root / "missing.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest("Symlink unavailable: " + str(error))
        return link, target

    def run_cli(self, output):
        args = ["check", "--k3-root", "unused", "--adobe", "unused-a", "--matrix", "unused-m", "--output", str(output)]
        with patch.object(sys, "argv", args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            dcp.main()
        self.assertEqual(result.exception.code, 1)

    def test_initial_dangling_symlink_rejected_before_inputs(self):
        link, target = self.dangling()
        with patch.object(dcp, "load_record") as load, patch.object(dcp, "analyze") as analyze:
            self.run_cli(link)
            load.assert_not_called()
            analyze.assert_not_called()
        self.assertFalse(os.path.lexists(target))

    def test_late_dangling_symlink_rejected_before_write(self):
        output = self.root / "result.json"
        target = self.root / "missing.json"
        def analyze(_):
            self.dangling()
            actual = deepcopy(dcp.validate_report(dcp.load_record()))
            actual.pop("inputs_unchanged_after_analysis")
            return actual
        with patch.object(dcp, "analyze", side_effect=analyze):
            self.run_cli(output)
        self.assertFalse(os.path.lexists(target))

    def test_existing_output_preserved(self):
        output = self.root / "existing.json"
        output.write_bytes(b"keep")
        with self.assertRaises(ValueError): dcp.write_result(output, {})
        self.assertEqual(output.read_bytes(), b"keep")

    def test_optimized_python_rejected(self):
        result = subprocess.run([sys.executable, "-B", "-O", str(ROOT / "tools/check_q7_dcp_structure.py"), "--check-record"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run without -O", result.stderr)
        self.assertNotIn("PASS", result.stdout)

    def test_ci_record_cli_and_deterministic_builder(self):
        result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/check_q7_dcp_structure.py"), "--check-record"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)
        import build_q7_dcp_report
        page = ROOT / "reports/q7-dcp-structure.html"
        before = page.read_bytes()
        build_q7_dcp_report.main()
        self.assertEqual(page.read_bytes(), before)

    def test_json_line_endings_do_not_change_generated_html(self):
        import build_q7_dcp_report as build
        analysis = self.root / "analysis"
        analysis.mkdir()
        raw = (ROOT / "analysis/q7-dcp-structure.json").read_bytes().replace(b"\r\n", b"\n")
        (analysis / "q7-dcp-template.html").write_bytes((ROOT / "analysis/q7-dcp-template.html").read_bytes())
        with patch.object(dcp, "ROOT", self.root), patch.object(build, "ROOT", self.root):
            (analysis / "q7-dcp-structure.json").write_bytes(raw)
            build.main()
            before = (self.root / "reports/q7-dcp-structure.html").read_bytes()
            (analysis / "q7-dcp-structure.json").write_bytes(raw.replace(b"\n", b"\r\n"))
            build.main()
            self.assertEqual((self.root / "reports/q7-dcp-structure.html").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
