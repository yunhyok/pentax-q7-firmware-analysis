"""Verify the complete Q7-29 witness before reproducing sparse DCP interpolation.

SDK/DCP are separately supplied and never exported. No native SDK execution.
SPDX-License-Identifier: GPL-2.0-only
"""
if not __debug__:
    raise RuntimeError('The reused parser requires assertions; run without -O')

import argparse
from copy import deepcopy
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
from types import ModuleType
import zipfile

ROOT=Path(__file__).resolve().parents[1]
OBS_RAW='f95afd00938e66fd9cc64296174257473d4415d7e7e3243d115aae9bb3c6fbf1'
OBS_TYPED='87831a2abf58d06c7029b96475939322533fb395a1abfc637fe269ca853094a1'
PINS_SHA='eda6fcaf128f8f67e021c496f326538fc36acd2443fa758baf07597e8f671808'
MATH_SHA='f2b2490dc09b82aa1e0ab6d029d00dab5b5f9b0b2eb52e956c64ec1349a48fc8'
HELPER_SHA='c62f899abbbdf82ec7f186ce885bc1b5d4317d2cbc4686433edf5c5296df3765'
PARSER_SHA='83c9ea9d745a4ac12bba4164ff729aeb8e64bdd3783e8575727251758ee3a7e7'
PROBES=[(123.4,.456,.321),(359.9,.51,.63),(.1,.51,.63),(287.3,.999,.91),(47.2,.123,.007)]
HISTORICAL=['sources','q7_28_helper_sha256_lf','scope']


def require(condition,note):
    if not condition:raise ValueError(note)


def canonical(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')).hexdigest()


def capture(path,cap=2000000):
    require(stat.S_ISREG(path.stat().st_mode),'Regular input path required')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as f:
        info=os.fstat(f.fileno())
        require(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=cap,'Bounded regular descriptor required')
        raw=f.read(cap+1)
    require(len(raw)==info.st_size and len(raw)<=cap,'Input size changed or exceeded cap')
    return raw


def pinned(path,expected,cap=2000000,lf=False):
    raw=capture(path,cap)
    normalized=raw.replace(b'\r\n',b'\n') if lf else raw
    require(sha256(normalized).hexdigest()==expected,'Pinned identity differs: '+path.name)
    return raw,normalized


def load_module(path,expected):
    raw,source=pinned(path,expected,200000,True)
    module=ModuleType(path.stem);module.__file__=str(path)
    exec(compile(source,str(path),'exec'),module.__dict__)
    return module,{'sha256_raw':sha256(raw).hexdigest(),'sha256_lf':expected}


def source_pins():
    _,raw=pinned(ROOT/'analysis/q7-dcp-interpolation-sources.json',PINS_SHA,100000,True)
    return json.loads(raw)


def check_observations(observations):
    require(canonical(observations)==OBS_TYPED,'Complete typed research-29 witness differs')
    raw=(json.dumps(observations,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
    require(sha256(raw).hexdigest()==OBS_RAW,'Complete serialized research-29 witness differs')
    return observations


def publication_metadata():
    source_pins()
    _,math_source=pinned(ROOT/'tools/q7_dcp_interpolation_math.py',MATH_SHA,200000,True)
    return {'task':'Q7-DCP-INTERPOLATION-PUBLIC-30','research_observations_raw_sha256':OBS_RAW,
            'research_observations_typed_canonical_sha256':OBS_TYPED,
            'research_code_sha256':{'replay.py':'a5f66446b0cee00cc1e049b086c972dcdd150419a8fb24a99e7b2d038a41f100','interpolate.py':'e0e5a2fa7128c3b270373553d5d48f707019a6c39c4c8bff97b65f4551a39a70','reference.py':'5c6943589849524d1081eb2d94418234ad70fc91c11d7e2305872f7af8edbe13'},
            'public_checker_sha256_lf':sha256(capture(Path(__file__),200000).replace(b'\r\n',b'\n')).hexdigest(),
            'public_math_sha256_lf':sha256(math_source).hexdigest(),'public_source_pins_sha256_lf':PINS_SHA,
            'current_public_structure_helper_sha256_lf':HELPER_SHA,'external_parser_sha256_lf':PARSER_SHA,
            'historical_fields_preserved_without_reobserving_original_environment':HISTORICAL,
            'numeric_contract':'Python binary64 versus Decimal 50 digits; no SDK real32 bit-identity or Lightroom equivalence',
            'source_contract':'selected 8 members of exact supplied SDK ZIP; no extraction or original local SDK checkout required',
            'output_contract':'lexists before inputs and immediately before xb; no general concurrent-path-race guarantee'}


def validate_report(record):
    require(set(record) in ({'schema','observations','_publication'},{'schema','observations','_publication','_reproduction'}),'Unknown public envelope fields')
    check_observations(record['observations'])  # Full typed witness before any subset/projection.
    require(record['schema']=='q7-dcp-interpolation-public-v1','Public schema differs')
    require(canonical(record['_publication'])==canonical(publication_metadata()),'Public metadata differs')
    if '_reproduction' in record:
        r=record['_reproduction']
        require(set(r)=={'sdk_zip_sha256','sdk_members_verified','dcp_sha256','dcp_filename','helper_capture','parser_capture','public_source_pins_sha256_lf','all_observations_preserved','historical_fields_not_reobserved','native_SDK_executed'},'Reproduction fields differ')
        require(type(r['sdk_members_verified']) is int and r['sdk_members_verified']==8,'Source count differs')
        require(r['all_observations_preserved'] is True and r['native_SDK_executed'] is False,'Execution status differs')
        require(r['historical_fields_not_reobserved']==HISTORICAL,'Historical scope differs')
        require(isinstance(r['dcp_filename'],str),'DCP label required')
        require(r['sdk_zip_sha256']==source_pins()['sdk_zip']['sha256'] and r['dcp_sha256']==record['observations']['dcp']['sha256'],'Reproduction input identity differs')
        require(r['public_source_pins_sha256_lf']==PINS_SHA,'Reproduction source pin differs')
        for key,expected in [('helper_capture',HELPER_SHA),('parser_capture',PARSER_SHA)]:
            require(set(r[key])=={'sha256_raw','sha256_lf'} and r[key]['sha256_lf']==expected,'Captured code identity differs')
            digest=r[key]['sha256_raw']
            require(isinstance(digest,str) and len(digest)==64 and all(x in '0123456789abcdef' for x in digest),'Invalid raw code digest')
    return record['observations']


def load_record(path=None):
    record=json.loads(capture(path or ROOT/'analysis/q7-dcp-interpolation.json',100000))
    validate_report(record)
    return record


def verify_sdk(path,pins):
    raw,_=pinned(path,pins['sdk_zip']['sha256'],pins['sdk_zip']['bytes'])
    require(len(raw)==pins['sdk_zip']['bytes'],'SDK ZIP size differs')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in pins['sources']:
            member=archive.getinfo(item['member'])
            require(member.file_size==item['bytes'] and member.file_size<=2000000,'SDK member size differs')
            data=archive.read(member)
            require(sha256(data).hexdigest()==item['sha256'],'SDK member identity differs')
            lines=data.splitlines(keepends=True)
            for span in item['spans']:
                require(sha256(b''.join(lines[span['first_line']-1:span['last_line']])).hexdigest()==span['sha256'],'SDK source span differs')
    return len(pins['sources'])


def reproduce(args,record):
    old=validate_report(record)  # Also guard programmatic callers before input reads.
    pins=source_pins();members=verify_sdk(args.sdk,pins)
    math_module,_=load_module(ROOT/'tools/q7_dcp_interpolation_math.py',MATH_SHA)
    helper,helper_capture=load_module(args.q7_root/'tools/check_q7_dcp_structure.py',HELPER_SHA)
    parser,parser_capture=load_module(args.k3_root/'inspect_adobe_profiles.py',PARSER_SHA)
    parser.TAGS.update(helper.EXTRA_TAGS)
    data,_=pinned(args.dcp,old['dcp']['sha256'])
    metadata,values=helper.inspect(data,parser)
    for name in ['ProfileHueSatMapEncoding','ProfileLookTableEncoding']:
        require(not metadata['optional_presence'][name],'Expected absent encoding tag')
    rows=[];errors=[]
    for name in ['ProfileHueSatMapData1','ProfileHueSatMapData2','ProfileLookTableData']:
        table=metadata['tables'][name];dims=table['dimensions_hsv']
        require(dims==([36,8,16] if name=='ProfileLookTableData' else [90,30,1]),'Table dimensions differ')
        require(table['zero_saturation_value_all_one'] and table['nonnegative_scales'],'SDK SetDelta/domain prerequisite differs')
        for hsv in PROBES:
            coeff=math_module.interpolate(values[name],dims,hsv)
            reference=math_module.reference(values[name],dims,hsv)
            error=max(abs(a-b) for a,b in zip(coeff,reference));errors.append(error)
            require(error<1e-10,'Decimal cross-check failed')
            rows.append({'table':name,'input_hsv_degrees':list(hsv),'weighted_coefficients_degrees_scale_scale':coeff,'derived_output_hsv_degrees':math_module.apply_linear(hsv,coeff),'decimal_reference_max_abs_error':error})
    actual=deepcopy(old)  # Preserve declared historical fields, including old helper provenance.
    actual['dcp']={'sha256':sha256(data).hexdigest(),'bytes':len(data),'encoding_tags_present':{n:metadata['optional_presence'][n] for n in ['ProfileHueSatMapEncoding','ProfileLookTableEncoding']},'sdk_default_encoding':{'name':'encoding_Linear','value':0},'tables':metadata['tables']}
    actual['parser_sha256_lf']=PARSER_SHA;actual['probes']=rows;actual['probe_count']=len(rows);actual['independent_reference_max_abs_error']=max(errors)
    check_observations(actual)
    result=deepcopy(record);result['observations']=actual
    result['_reproduction']={'sdk_zip_sha256':pins['sdk_zip']['sha256'],'sdk_members_verified':members,'dcp_sha256':sha256(data).hexdigest(),'dcp_filename':args.dcp.name,'helper_capture':helper_capture,'parser_capture':parser_capture,'public_source_pins_sha256_lf':PINS_SHA,'all_observations_preserved':True,'historical_fields_not_reobserved':HISTORICAL,'native_SDK_executed':False}
    validate_report(result)
    return result


def output_preflight(path):
    require(not os.path.lexists(path) and path.parent.is_dir(),'Output must be new, including no dangling link')


def write_result(path,result):
    payload=(json.dumps(result,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()
    output_preflight(path)
    with path.open('xb') as f:f.write(payload)
    return sha256(payload).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check-record',action='store_true')
    p.add_argument('--q7-root',type=Path,default=ROOT)
    for option in ['k3-root','sdk','dcp','output']:p.add_argument('--'+option,type=Path)
    args=p.parse_args()
    try:
        if args.check_record:
            require(all(getattr(args,n) is None for n in ['k3_root','sdk','dcp','output']),'Do not mix check and replay')
            load_record();print('Complete typed research-29 witness and public metadata: PASS');return
        require(all(getattr(args,n) is not None for n in ['k3_root','sdk','dcp','output']),'Replay needs --k3-root --sdk --dcp --output')
        output_preflight(args.output)
        record=load_record();result=reproduce(args,record)
        digest=write_result(args.output,result)
        print(json.dumps({'status':'passed','sha256':digest,'probes':15,'complete_research_observations_preserved':True,'native_SDK_executed':False}))
    except (OSError,ValueError,zipfile.BadZipFile) as error:p.exit(1,str(error)+'\n')


if __name__=='__main__':main()
