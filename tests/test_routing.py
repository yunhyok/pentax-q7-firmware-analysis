import copy
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from verify_routing import verify_words


class WordEvidenceTests(unittest.TestCase):
    def test_original_and_decoded_coordinates(self):
        segments = [('E03',0x1000,struct.pack('<II',1,0x0c103318),0x200),
                    ('E04',0x8000,struct.pack('<I',0x8040a008),None)]
        doc = {'nested':[{'va':'0x1004','u32le_word':'0x0c103318','segment':'E03','original_file_offset':'0x204'},
                         {'va':'0x8000','u32le_word':'0x8040a008','segment':'E04','decoded_offset':'0x0'}]}
        self.assertEqual(verify_words(doc,segments),2)
        for key,value in [('va','0x1008'),('u32le_word','0x0'),('segment','E04'),('original_file_offset','0x4')]:
            broken = copy.deepcopy(doc)
            broken['nested'][0][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                verify_words(broken,segments)


if __name__ == '__main__':
    unittest.main()
