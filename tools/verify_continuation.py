"""Validate NAND continuation and indexed shape raster evidence against original bytes."""
import hashlib
import json
import struct
from build_deep_report import read
from check_burn_continuation import validate_report as validate_burn
from check_colorspace_raster import validate_report as validate_raster
from inspect_q7 import parse_elf
from q7_symbols import SHA
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    burn, raster = read('burn-continuation.json'), read('colorspace-raster.json')
    validate_burn(burn['bounded_replay'])
    validate_raster(raster['replay'])
    for doc, keys, expected in (
        (burn, ('selected_functions', 'evidence', 'fixture_configuration', 'source_reconstruction'), '2094459398c7fb44fbde2806d4515cbdd6bcaa3745491cc9c6bb3a5c35a06dce'),
        (raster, ('selected_functions','duplicate_named_ranges','context_template','evidence'), 'b1da523c89a638a42fc25ff314ecc0007182819dbea7f1758ccc17a3f592b2d4'),
    ):
        assert doc['input_sha256'] == SHA
        assert hashlib.sha256(json.dumps([doc[k] for k in keys],sort_keys=True,separators=(',',':')).encode()).hexdigest() == expected
    assert len(list(witnesses(burn))) == 116 and len(list(witnesses(raster))) == 50
    if firmware is None: return
    assert hashlib.sha256(firmware).hexdigest() == SHA and decoded is not None
    boot, symbols = parse_elf(firmware, 0x200)
    assert boot['sha256_referenced_bytes'] == burn['boot_elf_sha256']
    segments = [('E01',s['virtual_address'],firmware[s['file_offset']:s['file_offset']+s['file_size']],s['file_offset'])
                for s in boot['segments'] if s['type']==1]
    assert verify_words(burn,segments) == 116
    typed = [f for f in burn['selected_functions'] if 'section_index' in f]
    assert len(typed) == 4
    for f in typed:
        symbol, = [s for s in symbols if s['name']==f['name'] and s['type']==2 and s['size']>0]
        assert (symbol['value'],symbol['size'],symbol['section_index']) == (f['address'],f['size'],f['section_index'])
        section = boot['sections'][f['section_index']]
        assert section['name'] == f['section_name']
        assert int(f['original_file_offset'],16) == section['file_offset']+f['address']-section['virtual_address']
    for f in burn['selected_functions']:
        off = int(f['original_file_offset'],16)
        assert hashlib.sha256(firmware[off:off+f['size']]).hexdigest() == f['sha256']
        assert any(base <= f['address'] < f['candidate_end'] <= base+len(body) and off == fileoff+f['address']-base
                   for _,base,body,fileoff in segments)
    source = firmware[0x2400C0:0x2600C0]
    patched = b'\xff'*512 + source[512:]
    reconstruction = burn['source_reconstruction']
    assert hashlib.sha256(patched).hexdigest() == reconstruction['main_sha256']
    assert sum(a != b for a,b in zip(source,patched,strict=True)) == reconstruction['main_changed_bytes'] == 512
    scratch = bytearray(source[:512])
    struct.pack_into('<I',scratch,0x54,135)
    scratch[0x58:0xD8] = b'\xff'*128
    assert sum(a != b for a,b in zip(source[:512],scratch,strict=True)) == reconstruction['direct_first512_changed_bytes'] == 132
    assert hashlib.sha256(scratch+b'\xff'*1536).hexdigest() == reconstruction['direct_sha256'] == burn['bounded_replay']['cases'][-1]['pending_storage_data_sha256']
    from build_analysis_elf import PLAIN, DECODED
    from trace_q7 import trace
    segments = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(raster,segments) == 50
    assert trace(firmware,[f['name'] for f in raster['selected_functions']],decoded)['functions'] == raster['selected_functions']
    for r in (*raster['duplicate_named_ranges'], raster['context_template']):
        address, size = int(r['va'],16), r['length_bytes']
        matches = [(name,base,data,off) for name,base,data,off in segments if base <= address < address+size <= base+len(data)]
        assert len(matches) == 1
        name,base,data,off = matches[0]
        field = 'decoded_offset' if off is None else 'original_file_offset'
        assert name == r['segment'] and int(r[field],16) == address-base+(off or 0)
        assert hashlib.sha256(data[address-base:address-base+size]).hexdigest() == r['sha256']
    print('Continuation/raster:166 original words,9 E01 extents,22 named/2 duplicate main extents,1 template reproduced')


if __name__ == '__main__':
    verify()
    print('Continuation/raster metadata: PASS')
