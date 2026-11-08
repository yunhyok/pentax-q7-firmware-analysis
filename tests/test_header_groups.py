"""Reject altered header event ranges, digests and duplicate program counters."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from check_burn_header import validate_report


class HeaderGroupTests(unittest.TestCase):
    def test_complete_group_provenance_is_pinned(self):
        original=json.loads((ROOT/'analysis/header-hash.json').read_text(encoding='utf-8'))['header_replay']
        validate_report(original)
        mutations=(('min_offset',999999),('min_offset',935),('end_exclusive',-1),
                   ('offset_size_data_sha256','not-a-sha256'),('offset_size_data_sha256','0'*64),
                   ('duplicate',None),('reorder',None))
        for key,value in mutations:
            changed=deepcopy(original)
            groups=changed['trace']['groups']
            if key=='duplicate': groups.append(deepcopy(groups[0]))
            elif key=='reorder': groups.reverse()
            else: groups[0][key]=value
            with self.subTest(key=key,value=value), self.assertRaises(AssertionError):
                validate_report(changed)


if __name__=='__main__': unittest.main()
