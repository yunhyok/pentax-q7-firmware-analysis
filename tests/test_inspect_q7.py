import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from inspect_q7 import parse_elf, inspect, entropy


def fixture():
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, 0x80000000, 52, 0, 0, 52, 32, 1, 40, 0, 0)
    segment = struct.pack("<8I", 1, 84, 0x80000000, 0x80000000, 4, 8, 5, 4)
    return ident + header + segment + b"CODE"


class InventoryTest(unittest.TestCase):
    def test_embedded_offset_and_entry(self):
        elf, symbols = parse_elf(bytes(512) + fixture(), 512)
        self.assertEqual(elf["entry_file_offsets"], [596])
        self.assertEqual(elf["referenced_end"], 600)
        self.assertEqual(elf["segments"][0]["memory_size"], 8)
        self.assertEqual(symbols, [])

    def test_bounds_and_truncated_header(self):
        for data in (fixture()[:20], fixture()[:-1]):
            with self.assertRaises(ValueError):
                parse_elf(data, 0)

    def test_mem_size_rejected(self):
        data = bytearray(fixture())
        struct.pack_into("<I", data, 52 + 20, 2)
        with self.assertRaises(ValueError):
            parse_elf(data, 0)

    def test_false_magic_not_an_elf(self):
        report, _ = inspect(b"\x7fELFDllMutex" + bytes(100))
        self.assertEqual(report["elf_magic_count"], 1)
        self.assertEqual(report["accepted_elf_count"], 0)

    def test_unsupported_endian(self):
        data = bytearray(fixture())
        data[5] = 2
        with self.assertRaises(ValueError):
            parse_elf(data, 0)

    def test_entropy(self):
        self.assertEqual(entropy(b"a" * 100), 0)
        self.assertEqual(entropy(bytes(range(256))), 8)

    def test_relocatable_symbols_and_bad_strings(self):
        data = bytearray(52 + 3 * 40 + 32 + 6)
        data[:16] = b"\x7fELF\x01\x01\x01" + bytes(9)
        struct.pack_into("<HHIIIIIHHHHHH", data, 16, 1, 8, 1, 0, 0, 52, 0, 52, 0, 0, 40, 3, 0)
        struct.pack_into("<10I", data, 92, 0, 2, 0, 0, 172, 32, 2, 1, 4, 16)
        struct.pack_into("<10I", data, 132, 0, 3, 0, 0, 204, 6, 0, 0, 1, 0)
        struct.pack_into("<IIIBBH", data, 188, 1, 0x20, 8, 0x12, 0, 1)
        data[204:] = b"\0func\0"
        elf, symbols = parse_elf(data, 0)
        self.assertEqual(elf["symbol_count"], 2)
        self.assertEqual(elf["defined_function_symbol_count"], 1)
        self.assertEqual(symbols[1]["value"], 0x20)
        self.assertEqual(elf["entry_file_offsets"], [])
        data[-1] = 65
        with self.assertRaises(ValueError):
            parse_elf(data, 0)


if __name__ == "__main__":
    unittest.main()
