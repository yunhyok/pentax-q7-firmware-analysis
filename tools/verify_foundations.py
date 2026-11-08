"""Verify lens/loader fixtures and optionally reproduce original code witnesses."""
import hashlib
import struct
from build_deep_report import read
from check_burn_input import validate_report as validate_burn
from check_lens_policy import validate_report as validate_lens
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA
from verify_implementation import verify_boot_functions
from verify_routing import witnesses,verify_words


def verify(firmware=None,decoded=None):
    loader,lens=read('loader-foundation.json'),read('lens-foundation.json')
    validate_burn(loader['replay']);validate_lens(lens['replay'])
    assert loader['input_sha256']==lens['input_sha256']==SHA
    assert lens['analysis_elf_sha256']==ELF_SHA256
    assert len(lens['selected_functions'])==lens['validation']['function_count']==67
    assert len(list(witnesses(lens)))==lens['validation']['original_word_witness_count']==214
    assert sum(len(lens['replay'][k]) for k in ('capability_cases','data_cases','speed_cases','acknowledgement_cases','completion_cases'))==32
    assert len(loader['boot_selected_functions'])==17 and len(loader['anonymous_functions'])==2
    assert len(list(witnesses(loader)))==loader['validation']['word_count']==117
    assert len(loader['file_evidence'])==20
    p=loader['payload_accounting']
    assert (p['code_file_sectors']+255)//256==p['code_chunk_count']==10
    assert (p['resource_a_file_sectors']+255)//256==p['resource_a_chunk_count']==125
    assert p['total_chunks']==p['code_chunk_count']+p['resource_a_chunk_count']==135
    assert p['payload_size']==p['total_chunks']*p['chunk_bytes']==0x10e0000
    assert int(p['payload_start'],16)+10*p['chunk_bytes']==int(p['resource_a_start'],16)
    assert int(p['first_resource_elf_start'],16)-int(p['resource_a_start'],16)==0x200
    for f in loader['boot_selected_functions']+loader['anonymous_functions']+lens['selected_functions']:
        assert f['candidate_end']-f['address']==f['size']>0
        assert len(f['sha256'])==64
    if firmware is None:return
    from build_analysis_elf import PLAIN,DECODED
    from inspect_q7 import parse_elf
    from trace_q7 import trace
    assert hashlib.sha256(firmware).hexdigest()==SHA and decoded is not None
    segments=[('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(lens,segments)==214
    assert trace(firmware,[f['name'] for f in lens['selected_functions']],decoded)['functions']==lens['selected_functions']
    boot,symbols=parse_elf(firmware,0x200)
    assert boot['sha256_referenced_bytes']==loader['boot_elf_sha256']==loader['replay']['boot_elf_sha256']
    segments=[('E01',s['virtual_address'],firmware[s['file_offset']:s['file_offset']+s['file_size']],s['file_offset']) for s in boot['segments'] if s['type']==1]
    assert verify_words(loader,segments)==117
    verify_boot_functions(firmware,boot,symbols,loader['boot_selected_functions'])
    for f in loader['anonymous_functions']:
        off=int(f['original_file_offset'],16)
        assert hashlib.sha256(firmware[off:off+f['size']]).hexdigest()==f['sha256']
        assert any(base<=f['address']<f['candidate_end']<=base+len(body) and off==fileoff+f['address']-base for _,base,body,fileoff in segments)
    for w in loader['file_evidence']:
        assert struct.unpack_from('<I',firmware,int(w['original_file_offset'],16))[0]==int(w['u32le_word'],16)
    h=loader['header'];off=int(h['original_file_offset'],16)
    assert hashlib.sha256(firmware[off:off+h['scope_size']]).hexdigest()==h['sha256']
    for field in h['fields']:
        assert struct.unpack_from('<I',firmware,off+int(field['header_offset'],16))[0]==field['value']
    print('Lens/loader: 331 VA words, 20 file words, 67 main / 17 typed E01 / 2 anonymous extents reproduced')


if __name__=='__main__':
    verify()
    print('Lens/loader fixtures and metadata: PASS')
