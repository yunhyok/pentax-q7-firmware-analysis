"""Check independent packed-pixel ordering and glyph tool output guards."""
from pathlib import Path
from copy import deepcopy
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import check_colorspace_glyph as glyph
import verify_glyph


class GlyphTests(unittest.TestCase):
    def test_source_links_and_observations_reject_drift(self):
        docs = {n:json.loads((ROOT/'analysis'/n).read_text(encoding='utf-8'))
                for n in ('colorspace-glyph.json','colorspace-render.json')}
        verify_glyph.verify()
        for kind in ('source','target','pixel'):
            changed = deepcopy(docs)
            doc = changed['colorspace-glyph.json']
            if kind == 'source':
                doc['input_reference']['line']['va'] = '0x8092da84'
            elif kind == 'target':
                doc['selected_functions'][2]['address'] += 4
            else:
                doc['bounded_replay']['cases'][1]['changed_bytes'] += 1
            with self.subTest(kind=kind), patch.object(verify_glyph,'read',side_effect=changed.__getitem__), self.assertRaises(AssertionError):
                verify_glyph.verify()

    def test_packed_codes_keep_transparency_and_map_indices(self):
        blob = bytearray(0x146+768)
        blob[:10] = b'LatinFont\0'
        for offset, value in ((0x20,0x202),(0x24,64),(0x2C,48),(0x40,0x54),
                              (0x44,0x9C),(0x4C,0x146),(0x68,1),(0x90,0xAA)):
            struct.pack_into('<I', blob, offset, value)
        blob[0x37], blob[0x9C], blob[0x146] = 2, 4, 0b00011011
        actual, rows = glyph.packed_oracle(blob, (0,))
        expected = bytearray([glyph.FILL])*(glyph.WIDTH*glyph.HEIGHT)
        offset = 64*glyph.WIDTH+96
        expected[offset+1:offset+4] = bytes((2,1,3))
        self.assertEqual(actual, expected)
        self.assertEqual(rows[0]['changed_bytes'], 3)
        with self.assertRaises(AssertionError):
            glyph.packed_oracle(blob, (170,))

    def test_output_guard_precedes_both_missing_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output, target = Path(directory)/'out.json', Path(directory)/'absent.json'
            try:
                output.symlink_to(target)
            except OSError as error:
                self.skipTest(str(error))
            for optimized in (False, True):
                result = subprocess.run([sys.executable,*(['-O'] if optimized else []),
                                         str(ROOT/'tools/check_colorspace_glyph.py'),
                                         'missing.bin','missing.elf','--output',str(output)],
                                        capture_output=True,text=True,timeout=15,cwd=ROOT)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('replay requires assertions' if optimized else 'output must not exist', result.stderr)
                self.assertTrue(os.path.lexists(output))
                self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
