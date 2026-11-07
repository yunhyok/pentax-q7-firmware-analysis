import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from decode_segments import HEADER, decode_segment


LITERAL_A = (ord("A") << 2) | 3
END = 0x403
COPY_3 = 0x80f
DISTANCE_1 = 3
DENSE = ((2 << 15) | (2 << 11) | 4, LITERAL_A, COPY_3, END, LITERAL_A)
COMPACT = ((2 << 15) | (1 << 11) | 1, LITERAL_A, 0x9837, END)


def block(size, payload, literals=DENSE, distances=(DISTANCE_1,)):
    tables = literals + distances
    return (HEADER.pack(2, size, len(payload), 4 * len(literals), 4 * len(distances))
            + struct.pack(f"<{len(tables)}I", *tables) + payload)


def decode(stream, size):
    file_offset = 8
    segment = {"file_offset": file_offset, "file_size": len(stream),
               "virtual_address": 0x80000100, "memory_size": size}
    return decode_segment(bytes(file_offset) + stream, segment)


class DecodeSegmentsTest(unittest.TestCase):
    def test_overlapping_copy_and_cross_block_history(self):
        first = block(4, b"\x18")  # 00 literal, 01 copy, 10 end.
        second = block(3, b"\x60")  # 01 copy from earlier block, 10 end.
        decoded, blocks = decode(first + second, 7)
        self.assertEqual(decoded, b"AAAAAAA")
        self.assertEqual([item["used_bits"] for item in blocks], [6, 4])
        self.assertEqual(blocks[0]["file_end"], blocks[1]["file_offset"])
        self.assertEqual(blocks[1]["virtual_address"], 0x80000104)
        self.assertEqual(blocks[1]["virtual_end"], 0x80000107)

    def test_compact_table_and_length_extra(self):
        # 0 literal, 10 copy with an extra bit of 1, 11 end.
        decoded, _ = decode(block(15, b"\x5c", COMPACT), 15)
        self.assertEqual(decoded, b"A" * 15)

    def test_reject_malformed_streams(self):
        for source, size, error in (
            (block(3, b"\x60"), 3, "copy distance"),
            (block(5, b"\x18"), 5, "output length mismatch"),
            (block(1, b"\x01"), 1, "missing end marker"),
            (block(4, b"\x19"), 4, "nonzero padding"),
            (block(4, b"\x18")[:-1], 4, "exceeds segment file range"),
            (block(4, b"\x18", (DENSE[0] + 32, *DENSE[1:])), 4, "outside table"),
            (block(4, b"\x18"), 3, "output length"),
        ):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                decode(source, size)


if __name__ == "__main__":
    unittest.main()
