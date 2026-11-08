"""Protect the distinct update implementations and replay output boundary."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import verify_update_service


class UpdateServiceTests(unittest.TestCase):
    def test_callback_namespace_and_return_records_are_pinned(self):
        docs = {n:json.loads((ROOT/'analysis'/n).read_text(encoding='utf-8'))
                for n in ('update-service.json','rebuild-evidence.json')}
        verify_update_service.verify()
        for kind in ('callback','raw_result','async_flag','path'):
            changed = deepcopy(docs)
            doc = changed['update-service.json']
            if kind == 'callback':
                doc['prior_E01']['selected_callback'] = '0x805dd7b8'
            elif kind == 'raw_result':
                doc['bounded_replay']['bridge_cases'][9]['result'] = 254
            elif kind == 'async_flag':
                doc['bounded_replay']['bridge_cases'][10]['updating'] = 0
            else:
                doc['resource_ranges'][0]['va'] = '0x807f2908'
            with self.subTest(kind=kind),patch.object(verify_update_service,'read',side_effect=changed.__getitem__),self.assertRaises(AssertionError):
                verify_update_service.verify()

    def test_dangling_output_and_optimized_mode_fail_before_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            output,target = Path(directory)/'out.json',Path(directory)/'absent.json'
            try:
                output.symlink_to(target)
            except OSError as error:
                self.skipTest(str(error))
            for optimized in (False,True):
                result = subprocess.run([sys.executable,*(['-O'] if optimized else []),
                                         str(ROOT/'tools/check_update_service.py'),
                                         'missing.bin','missing.elf','--output',str(output)],
                                        capture_output=True,text=True,timeout=15,cwd=ROOT)
                self.assertEqual(result.returncode,2,result.stderr)
                self.assertIn('replay requires assertions' if optimized else 'output must not exist',result.stderr)
                self.assertTrue(os.path.lexists(output))
                self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
