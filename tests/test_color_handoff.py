"""A disabled assertion engine must never publish a successful replay result."""
from pathlib import Path
import subprocess
import sys
import unittest


class OptimizedReplayTests(unittest.TestCase):
    def test_optimized_python_is_rejected_before_reading_input(self):
        root=Path(__file__).resolve().parents[1]
        for module in ('check_color_handoff','check_fiplib_coefficients','check_submit_choice','check_fc1_enable','check_hdr_passes'):
            with self.subTest(module=module):
                result=subprocess.run([sys.executable,'-O','-c',
                    "import sys; from pathlib import Path; sys.path.insert(0,'tools'); "
                    f"from {module} import replay; replay(Path('not-an-input.elf'))"],
                    cwd=root,capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('requires assertions',result.stderr)


if __name__=='__main__': unittest.main()
