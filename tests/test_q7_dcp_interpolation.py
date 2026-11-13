import math
import unittest
from pathlib import Path
import os,runpy,copy,json,hashlib,subprocess,sys,tempfile,stat
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(os.environ.get('Q7_INTERPOLATION_CANDIDATE',Path(__file__).resolve().parents[1]))
API=runpy.run_path(str(ROOT/'tools/check_q7_dcp_interpolation.py'))
MATH=runpy.run_path(str(ROOT/'tools/q7_dcp_interpolation_math.py'))
interpolate,apply_linear,reference=(MATH[n] for n in ('interpolate','apply_linear','reference'))
sys.path.insert(0,str(ROOT/'tools'))
from build_q7_dcp_interpolation_report import render


def synthetic(dims, function):
    nh, ns, nv = dims
    return [x for v in range(nv) for h in range(nh) for s in range(ns) for x in function(h,s,v)]


class InterpolationChecks(unittest.TestCase):
    def close(self, a, b):
        for x, y in zip(a, b):
            self.assertAlmostEqual(x, y, delta=1e-10)

    def test_storage_axes_and_grid_corner(self):
        dims = (4, 3, 2)
        table = synthetic(dims, lambda h,s,v: (100*v+10*h+s, 1.0, 1.0))
        self.close(interpolate(table,dims,(180,.5,1)), [121,1,1])

    def test_interior_trilinear_and_independent_reference(self):
        dims = (4, 3, 2)
        table = synthetic(dims, lambda h,s,v: (10*h+4*s+20*v,1+.1*h+.2*s+.3*v,1+.02*h+.03*s+.04*v))
        for hsv in [(45,.25,.25),(359.9,.73,.48),(0,0,0),(270,1,1),(91,.01,.99)]:
            self.close(interpolate(table,dims,hsv), reference(table,dims,hsv))
        self.close(interpolate(table,dims,(45,.25,.25)),[12,1.225,1.035])

    def test_circular_axis_wrap(self):
        dims=(4,2,1);table=synthetic(dims,lambda h,s,v:(10*h,1,1))
        self.close(interpolate(table,dims,(315,.5,.5)),[15,1,1])
        self.assertLess(abs(interpolate(table,dims,(359.999,.5,.5))[0]-interpolate(table,dims,(.001,.5,.5))[0]),.001)

    def test_hue_shift_components_use_linear_not_short_arc_average(self):
        dims=(2,2,1);table=synthetic(dims,lambda h,s,v:(170 if h==0 else -170,1,1))
        self.close(interpolate(table,dims,(90,.5,.5)),[0,1,1])

    def test_single_value_plane_can_change_value(self):
        dims=(1,2,1);table=synthetic(dims,lambda h,s,v:(0,1,2))
        lo=interpolate(table,dims,(0,.5,.2));hi=interpolate(table,dims,(0,.5,.8))
        self.close(lo,hi);self.close(lo,reference(table,dims,(0,.5,.2)))
        self.assertEqual(apply_linear((0,.5,.2),lo)[2],.4)
        self.assertEqual(apply_linear((0,.5,.8),hi)[2],1)

    def test_output_hue_wrap_and_saturation_value_clips(self):
        self.close(apply_linear((350,.9,.8),(20,2,2)),[10,1,1])
        self.close(apply_linear((5,.2,.4),(-20,1,.5)),[345,.2,.2])

    def test_invalid_domain_and_payload_rejected(self):
        for hsv in [(360,.5,.5),(-1,.5,.5),(0,1.1,.5),(0,.5,-.1),(math.nan,0,0)]:
            with self.assertRaises(ValueError):interpolate([0,1,1]*2,(1,2,1),hsv)
        with self.assertRaises(ValueError):interpolate([0,1,1],(1,2,1),(0,0,0))
        with self.assertRaises(ValueError):interpolate([0,1,math.inf]*2,(1,2,1),(0,0,0))


class WitnessAndInputChecks(unittest.TestCase):
    def setUp(self):
        self.record=API['load_record']()
        self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('Q7_INTERPOLATION_TEST_TMP'))
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)

    def test_full_typed_witness_before_projection(self):
        mutations=[]
        for key in self.record['observations']:
            bad=copy.deepcopy(self.record);del bad['observations'][key];mutations.append(bad)
        for key,value in [('probe_count',15.0),('extra',False),('scope',{})]:
            bad=copy.deepcopy(self.record);bad['observations'][key]=value;mutations.append(bad)
        bad=copy.deepcopy(self.record);bad['observations']['probes'][-1]['input_hsv_degrees'][2]=True;mutations.append(bad)
        bad=copy.deepcopy(self.record);bad['observations']['dcp']['sdk_default_encoding']['value']=False;mutations.append(bad)
        for bad in mutations:
            with self.subTest(observations=list(bad['observations'])):
                with self.assertRaises(ValueError):API['validate_report'](bad)
                with self.assertRaises(ValueError):render(bad)
                with patch.dict(API['reproduce'].__globals__,verify_sdk=lambda *a: self.fail('Input read before witness gate')):
                    with self.assertRaises(ValueError):API['reproduce'](SimpleNamespace(),bad)

    def test_preserved_history_and_current_helper_are_distinct(self):
        self.assertEqual(self.record['observations']['q7_28_helper_sha256_lf'],'059b7cda016c0015cc364696a82fd624c15fcb8acbc1858684cd40206dcf678e')
        self.assertEqual(self.record['_publication']['current_public_structure_helper_sha256_lf'],API['HELPER_SHA'])
        self.assertNotEqual(API['HELPER_SHA'],self.record['observations']['q7_28_helper_sha256_lf'])
        serialized=(json.dumps(self.record['observations'],ensure_ascii=False,indent=2)+'\n').encode()
        self.assertEqual(hashlib.sha256(serialized).hexdigest(),API['OBS_RAW'])

    def test_json_and_code_parse_the_captured_bytes(self):
        record_path=self.folder/'record.json';raw=json.dumps(self.record).encode();record_path.write_bytes(raw)
        real=API['capture']
        def capture_then_replace(path,cap):
            data=real(path,cap)
            if path==record_path:path.write_text('{}')
            return data
        with patch.dict(API['load_record'].__globals__,capture=capture_then_replace):
            self.assertEqual(API['load_record'](record_path),self.record)
        module_path=self.folder/'sample.py';source=b'VALUE = 17\n';module_path.write_bytes(source)
        def captured_module(path,cap):
            data=real(path,cap);path.write_text('raise RuntimeError("reread")');return data
        with patch.dict(API['load_module'].__globals__,capture=captured_module):
            module,_=API['load_module'](module_path,hashlib.sha256(source).hexdigest())
        self.assertEqual(module.VALUE,17)

    def test_bounds_regular_descriptor_and_line_endings(self):
        p=self.folder/'input';p.write_bytes(b'abc\r\n')
        with self.assertRaises(ValueError):API['capture'](p,4)
        with self.assertRaises(ValueError):API['capture'](self.folder,4)
        with patch.object(API['os'],'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFIFO,st_size=5)):
            with self.assertRaises(ValueError):API['capture'](p,5)
        self.assertEqual(API['pinned'](p,hashlib.sha256(b'abc\n').hexdigest(),5,True)[1],b'abc\n')
        record_path=self.folder/'record.json'
        record_path.write_bytes((json.dumps(self.record,indent=2)+'\n').replace('\n','\r\n').encode())
        self.assertEqual(API['load_record'](record_path),self.record)

    def test_invalid_sdk_identity_precedes_zip_parsing(self):
        p=self.folder/'fake.zip';p.write_bytes(b'not a zip')
        with patch.object(API['zipfile'],'ZipFile',side_effect=AssertionError('Unverified ZIP parsed')):
            with self.assertRaises(ValueError):API['verify_sdk'](p,API['source_pins']())

    def test_existing_and_hardlink_outputs_stop_before_inputs(self):
        original=self.folder/'original';original.write_bytes(b'keep')
        linked=self.folder/'linked';os.link(original,linked)
        argv=['checker','--k3-root','missing','--sdk','missing','--dcp','missing','--output']
        for output in (original,linked):
            with patch.object(sys,'argv',argv+[str(output)]),patch.dict(API['main'].__globals__,load_record=lambda: self.fail('Inputs read')):
                with self.assertRaises(SystemExit):API['main']()
        self.assertEqual(original.read_bytes(),b'keep')

    def test_dangling_and_late_link_outputs_are_rejected(self):
        output=self.folder/'output';target=self.folder/'missing'
        try:os.symlink(target,output)
        except OSError as error:self.skipTest('Host does not permit symlinks: '+str(error))
        with self.assertRaises(ValueError):API['output_preflight'](output)
        output.unlink();API['output_preflight'](output)
        os.symlink(target,output)
        with self.assertRaises(ValueError):API['write_result'](output,self.record)
        self.assertFalse(os.path.lexists(target));self.assertTrue(os.path.lexists(output))

    def test_xb_preserves_competing_regular_file(self):
        output=self.folder/'output';preflight=API['output_preflight']
        def compete(path):preflight(path);path.write_bytes(b'competitor')
        with patch.dict(API['write_result'].__globals__,output_preflight=compete):
            with self.assertRaises(FileExistsError):API['write_result'](output,self.record)
        self.assertEqual(output.read_bytes(),b'competitor')

    def test_optimized_cli_rejected_before_inputs(self):
        run=subprocess.run([sys.executable,'-B','-O',str(ROOT/'tools/check_q7_dcp_interpolation.py'),'--check-record'],capture_output=True,text=True)
        self.assertNotEqual(run.returncode,0);self.assertIn('run without -O',run.stderr)


if __name__=='__main__':unittest.main()
