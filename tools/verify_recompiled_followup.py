"""Check reconstructed C provenance, replay metadata and original Q7 witnesses."""
import hashlib
from build_deep_report import ROOT, read
from check_recompiled_numeric import SOURCE_SHA256, validate_report
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA
from check_numeric_package import UPDATE_SHA256, REBUILT_ELF_SHA256
from verify_routing import witnesses, verify_words


def verify(firmware=None, decoded=None):
    data = read('recompiled-numeric.json')
    validate_report(data['replay'])
    assert data['input_sha256'] == SHA and data['analysis_elf_sha256'] == ELF_SHA256
    source = (ROOT/'source/reconstructed/q7_numeric.c').read_bytes().replace(b'\r\n', b'\n')
    assert hashlib.sha256(source).hexdigest() == SOURCE_SHA256
    assert len(data['selected_functions']) == 7 and len(list(witnesses(data))) == 35
    attempt = data['package_attempt']
    assert attempt['segment'] == 'E04' and attempt['block'] == 154
    assert attempt['needed_bits'] == 79323 and attempt['needed_bytes'] == (79323+7)//8 == 9916
    assert attempt['capacity_bytes'] == 9856 and attempt['patch_bytes'] == 164
    assert attempt['output_written'] is False
    manifest = read('segment-decode.json')
    block = next(s for s in manifest['segments'] if s['name'] == 'E04')['blocks'][154]
    for key in ('file_offset', 'file_end', 'virtual_address', 'virtual_end'):
        assert int(attempt[key], 16) == block[key]
    for f in data['selected_functions']:
        assert f['candidate_end']-f['address'] == f['size'] > 0
    package=data['package_rebuild']
    assert package['output_sha256']==UPDATE_SHA256 and package['analysis_elf_sha256']==REBUILT_ELF_SHA256
    assert package['image_equals_replayed_overlay'] and package['all_decoded_bytes_and_layout_verified']
    assert (package['total_blocks'],package['unchanged_blocks'],package['segments'])==(448,446,4)
    assert package['decoded_difference_bytes']==142 and package['patch_bytes']==164
    assert [(b['block'],b['new_bits'],b['used_bytes'],b['zero_tail_bits']) for b in package['blocks']]==[(154,78817,9853,31),(155,78813,9852,35)]
    assert all(b['capacity_bytes']==9856 and b['used_bytes']==(b['new_bits']+7)//8 for b in package['blocks'])
    assert package['footer_after']['sum_matches'] and package['footer_after']['stored_sum']==0x65739c6d
    if firmware is None:
        return
    from build_analysis_elf import PLAIN, DECODED
    from trace_q7 import trace
    assert hashlib.sha256(firmware).hexdigest() == SHA and decoded is not None
    segments = [('E03', va, firmware[o:o+n], o) for o,va,n in PLAIN]
    segments += [(name[:-4], va, decoded[name[:-4]], None) for name,va,_ in DECODED]
    assert verify_words(data, segments) == 35
    assert trace(firmware, [f['name'] for f in data['selected_functions']], decoded)['functions'] == data['selected_functions']
    print('Recompiled Q13: 35 original words and 7 function hashes/transfers reproduced')


if __name__ == '__main__':
    verify()
    print('Recompiled Q13 metadata and C source: PASS')
