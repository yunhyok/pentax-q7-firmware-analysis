"""Synthetic fixed-table overflow, LZ overlap and malformed-input checks."""
from functools import lru_cache
from itertools import product
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from decode_segments import HEADER, decode_segment
from fixed_table_encode import copy_codes, encode_window, leaf_prefixes
from repack_q7 import pack_bits, rebuild_stream


class FixedTableTests(unittest.TestCase):
    def test_overflow_retokenizes_with_overlap_and_same_layout(self):
        leaves = [(x << 2) | 3 for x in (65, 66, 88)]
        leaves += [(n << 2) | 0x803 for n in (3, 7, 8)] + [0x403, 0x403]
        literal = struct.pack('<9I', (3 << 11) | 4, *[(3 << 15) | x for x in leaves])
        distance = struct.pack('<I', (1 << 15) | 3)
        source = HEADER.pack(2, 9, 2, len(literal), 4) + literal + distance + pack_bits('0001010110', 2)
        segment = dict(blocks=[dict(file_offset=0, file_end=len(source))])
        with self.assertRaisesRegex(ValueError, 'slot has 2'):
            rebuild_stream(source, segment, b'ABBBBBBBB')
        result, changed, _ = rebuild_stream(source, segment, b'ABBBBBBBB', [(1, 9)])
        self.assertEqual(result[:-2], source[:-2])
        self.assertEqual(len(result), len(source))
        decoded, _ = decode_segment(result, dict(file_offset=0, file_size=len(result), virtual_address=0x1000, memory_size=9))
        self.assertEqual(decoded, b'ABBBBBBBB')
        self.assertEqual(changed[0]['literal_repair_bits'], 30)
        self.assertEqual(changed[0]['new_bits'], 13)
        self.assertEqual(changed[0]['new_copy_tokens'], 1)

    def test_small_windows_match_exhaustive_cost_oracle(self):
        literals, lengths, distances = {65:'00', 66:'01'}, {3:'10', 4:'110'}, {1:'0', 2:'10', 3:'11'}
        count = 0
        for history in (b'A', b'AB', b'ABA'):
            for n in range(1, 8):
                for tail in product(b'AB', repeat=n):
                    target = history + bytes(tail)

                    @lru_cache(None)
                    def oracle(pos):
                        if pos == len(target):
                            return 0
                        options = [len(literals[target[pos]]) + oracle(pos + 1)]
                        for size, length_code in lengths.items():
                            for distance, distance_code in distances.items():
                                if distance > pos or pos + size > len(target):
                                    continue
                                decoded = bytearray(target[:pos])
                                for _ in range(size):
                                    decoded.append(decoded[-distance])
                                if decoded == target[:pos + size]:
                                    options.append(len(length_code) + len(distance_code) + oracle(pos + size))
                        return min(options)

                    bits, _ = encode_window(target, len(history), len(target), literals, lengths, distances)
                    self.assertEqual(len(bits), oracle(len(history)))
                    count += 1
        self.assertEqual(count, 762)

    def test_bad_tables_missing_codes_and_bounds_rejected(self):
        for table in ([], [0], [(1 << 11) | (100 << 2)]):
            with self.assertRaises(ValueError):
                leaf_prefixes(table, True)
        with self.assertRaises(ValueError):
            copy_codes([(3 << 15) | 0x80f], [])
        with self.assertRaisesRegex(ValueError, 'cannot be represented'):
            encode_window(b'Z', 0, 1, {65:'0'}, {}, {})
        for start, end in ((-1, 1), (0, 2), (1, 1)):
            with self.assertRaisesRegex(ValueError, 'invalid repair window'):
                encode_window(b'A', start, end, {65:'0'}, {}, {})

    def test_candidate_budget_is_shared_across_windows(self):
        budget = [1]
        encode_window(b'AAAA', 1, 4, {65:'00'}, {3:'1'}, {1:'0'}, budget)
        self.assertEqual(budget, [0])
        with self.assertRaisesRegex(ValueError, 'candidate budget exceeded'):
            encode_window(b'AAAA', 1, 4, {65:'00'}, {3:'1'}, {1:'0'}, budget)


if __name__ == '__main__':
    unittest.main()
