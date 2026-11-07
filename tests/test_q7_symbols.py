import sys
from pathlib import Path
import struct
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from q7_symbols import decode_symbols, read_file


class SymbolTest(unittest.TestCase):
    def test_aliases_preserved(self):
        rows = decode_symbols(struct.pack("<3I", 0, 16, 16), struct.pack("<3I", 0, 2, 4), b"a\0b\0c\0")
        self.assertEqual([r["name"] for r in rows], ["a", "b", "c"])
        self.assertEqual(rows[1]["address"], rows[2]["address"])

    def test_bad_offsets_order_and_termination(self):
        for a, o, s in [(b"123", b"123", b"x\0"), (struct.pack("<I", 1), struct.pack("<I", 1), b"ab\0"),
                        (struct.pack("<2I", 2, 1), struct.pack("<2I", 0, 0), b"a\0"),
                        (struct.pack("<I", 1), struct.pack("<I", 0), b"bad")]:
            with self.assertRaises(ValueError):
                decode_symbols(a, o, s)

    def test_fragmented_file_and_cycle(self):
        fat = struct.pack("<5H", 0xfff8, 0xffff, 4, 0xffff, 0xffff)
        g = dict(data_start=0, cluster_size=4)
        raw, spans = read_file(b"abcd----efgh", g, fat, dict(size=7, first_cluster=2))
        self.assertEqual(raw, b"abcdefg")
        self.assertEqual(len(spans), 2)
        bad = struct.pack("<5H", 0xfff8, 0xffff, 2, 0xffff, 0xffff)
        with self.assertRaises(ValueError):
            read_file(b"abcd----efgh", g, bad, dict(size=7, first_cluster=2))


if __name__ == "__main__":
    unittest.main()
