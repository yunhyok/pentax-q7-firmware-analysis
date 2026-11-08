"""Validate storage/readiness fixtures and reproduce original code witnesses."""
import hashlib
from build_deep_report import read
from check_burn_storage import validate_report
from check_lens_readiness import validate_report as validate_lens
from check_isp_registers import ELF_SHA256
from inspect_q7 import parse_elf
from q7_symbols import SHA
from verify_implementation import verify_boot_functions
from verify_routing import witnesses, verify_words


def verify(firmware=None,decoded=None):
    data=read('loader-storage.json')
    lens=read('lens-readiness.json')
    validate_report(data['replay'])
    validate_lens(lens['replay'])
    assert lens['input_sha256']==SHA and lens['analysis_elf_sha256']==ELF_SHA256
    assert len(list(witnesses(lens)))==153 and len(lens['selected_functions'])==33
    assert data['input_sha256']==SHA
    assert len(list(witnesses(data)))==83
    assert len(data['boot_selected_functions'])==8 and len(data['boot_anonymous_ranges'])==3
    for f in data['boot_selected_functions']+data['boot_anonymous_ranges']:
        assert f['candidate_end']-f['address']==f['size']>0
    if firmware is None:return
    assert hashlib.sha256(firmware).hexdigest()==SHA
    boot,symbols=parse_elf(firmware,0x200)
    assert boot['sha256_referenced_bytes']==data['boot_elf_sha256']==data['replay']['boot_elf_sha256']
    segments=[('E01',s['virtual_address'],firmware[s['file_offset']:s['file_offset']+s['file_size']],s['file_offset']) for s in boot['segments'] if s['type']==1]
    assert verify_words(data,segments)==83
    verify_boot_functions(firmware,boot,symbols,data['boot_selected_functions'])
    for f in data['boot_anonymous_ranges']:
        off=int(f['original_file_offset'],16)
        assert hashlib.sha256(firmware[off:off+f['size']]).hexdigest()==f['sha256']
        assert any(base<=f['address']<f['candidate_end']<=base+len(body) and off==fileoff+f['address']-base for _,base,body,fileoff in segments)
    print('Loader storage: 83 words, 8 typed and 3 anonymous E01 extents reproduced')
    from build_analysis_elf import PLAIN,DECODED
    from trace_q7 import trace
    assert decoded is not None
    segments=[('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(lens,segments)==153
    assert trace(firmware,[f['name'] for f in lens['selected_functions']],decoded)['functions']==lens['selected_functions']
    print('Lens readiness: 153 words and 33 function hashes/transfers reproduced')


if __name__=='__main__':
    verify()
    print('Storage/readiness metadata: PASS')
