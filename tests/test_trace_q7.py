import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from trace_q7 import transfer


class TransferTests(unittest.TestCase):
    def test_direct_and_delay_slot_region(self):
        self.assertEqual(transfer(0x0C000123, 0x8FFFFFFC), ("call", 0x9000048C))
        self.assertEqual(transfer(0x08000123, 0x80000000), ("jump", 0x8000048C))

    def test_signed_relative_and_indirect(self):
        self.assertEqual(transfer(0x0411FFFE, 0x80001000), ("conditional-call", 0x80000FFC))
        self.assertEqual(transfer(0x0040F809, 0x80001000), ("indirect-call", None))
        self.assertEqual(transfer(0x00400008, 0x80001000), ("indirect-jump", None))
        self.assertIsNone(transfer(0x03E00008, 0x80001000))


if __name__ == "__main__":
    unittest.main()
