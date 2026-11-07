import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_analysis_elf import assemble


class AnalysisElfTests(unittest.TestCase):
    def test_segment_offsets(self):
        data = assemble([(0x80001000, b"abcd"), (0x80002000, b"efghijkl")])
        self.assertEqual(data[:7], b"\x7fELF\x01\x01\x01")
        self.assertEqual(struct.unpack_from("<H", data, 44)[0], 2)
        for i, expected in enumerate((b"abcd", b"efghijkl")):
            fields = struct.unpack_from("<8I", data, 52 + 32 * i)
            self.assertEqual(data[fields[1]:fields[1] + fields[4]], expected)


if __name__ == "__main__":
    unittest.main()
