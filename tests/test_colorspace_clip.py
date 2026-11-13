"""Asset-free checks for the recorded Q7 clipping contract and replay guards."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
import check_colorspace_clip as clip


class ClipTests(unittest.TestCase):
    def test_published_contract(self):
        doc = clip.read_json(ROOT/'analysis/colorspace-clip.json')
        clip.validate_public(doc)
        self.assertEqual(doc['font_selection']['color_space_row_first_code'], 84)
        self.assertEqual(doc['font_selection']['glyph']['source_columns'],
                         [0,1,3,4,5,7,8,9,11,12,13,15,16,17,19,20,21,23])
        self.assertEqual(sum(c['executed_span_count'] for c in doc['cases']),224)
        cases = {case['name']:case for case in doc['cases']}
        self.assertEqual({k:cases[k]['store_count'] for k in ('left','right','top','bottom')},
                         dict(left=244,right=245,top=298,bottom=127))
        corner = doc['rectangular_counterexample']
        self.assertEqual(corner['ordinary_rectangle_store_count']-cases[corner['case']]['store_count'],8)
        self.assertEqual(corner['visible_x_inclusive'],[0,7])

    def test_typed_published_record_rejects_drift(self):
        doc = clip.read_json(ROOT/'analysis/colorspace-clip.json')
        for key,replacement in [('returned',1), ('store_count',425.0), ('frame_sha256','0'*64)]:
            with self.subTest(key=key):
                changed=deepcopy(doc)
                changed['cases'][0][key]=replacement
                with self.assertRaisesRegex(ValueError,'published evidence differs'):
                    clip.validate_public(changed)

    def test_projection_rejects_changed_complete_observation_before_access(self):
        class Unprojectable(dict):
            def __getitem__(self, key):
                raise AssertionError(f'premature projection: {key}')

        edges = Unprojectable(cases=[{'returned':True, 'executed_spans':[{'sha256':'correct'}]}])
        corner = Unprojectable(cases=[{'returned':True}])
        pins = {k:clip.digest(clip.canonical(v)) for k,v in [('edges',edges),('corner',corner)]}
        changed = Unprojectable(cases=[{'returned':1}])
        with patch.object(clip,'FULL_WITNESS_PINS',pins):
            with self.assertRaisesRegex(ValueError,'corner: complete typed native witness differs'):
                clip.project(edges,changed)
            bad_span = Unprojectable(cases=[{'returned':True, 'executed_spans':[{'sha256':'mutated'}]}])
            with self.assertRaisesRegex(ValueError,'edges: complete typed native witness differs'):
                clip.project(bad_span,corner)

    def test_all_project_sources_checked_before_any_exec(self):
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            first=b'raise RuntimeError("early execution")\n'
            later=b'{}'
            for name,data in [('tools/pentax_lz.py',first),('analysis/colorspace-attributes.json',later)]:
                target=directory/name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(data)
            pins = {'tools/pentax_lz.py':clip.digest(first),
                    'analysis/colorspace-attributes.json':clip.digest(b'{"expected":1}')}
            with patch.object(clip,'SOURCE_PINS',pins):
                with self.assertRaisesRegex(ValueError,'captured source identity: analysis/'):
                    clip.capture_sources(directory)

    def test_cli_guards_precede_missing_inputs(self):
        script = ROOT/'tools/check_colorspace_clip.py'
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'new.json'
            arguments = [str(script),'replay','missing-package','missing-elf',
                         '--stage','corner','--output',str(output)]
            optimized = subprocess.run([sys.executable,'-B','-O',*arguments],capture_output=True)
            self.assertEqual(optimized.returncode,2)
            self.assertIn(b'requires assertions',optimized.stderr)
            self.assertFalse(output.exists())
            output.write_text('sentinel',encoding='utf-8')
            exists = subprocess.run([sys.executable,'-B',*arguments],capture_output=True)
            self.assertEqual(exists.returncode,2)
            self.assertIn(b'output must not exist',exists.stderr)
            self.assertEqual(output.read_text(encoding='utf-8'),'sentinel')

    def test_package_capture_binds_length_and_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp)/'input'
            source.write_bytes(b'abcd')
            self.assertEqual(clip.capture(source,4,clip.digest(b'abcd')),b'abcd')
            with self.assertRaisesRegex(ValueError,'input identity'):
                clip.capture(source,4,clip.digest(b'abcx'))
            with self.assertRaisesRegex(ValueError,'exceeds size limit'):
                clip.capture(source,3,clip.digest(b'abc'))


if __name__ == '__main__':
    unittest.main()

