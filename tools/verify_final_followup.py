"""Check HDR selector/FC metadata and optionally reproduce original word evidence."""
import hashlib

from build_deep_report import read
from check_fiplib_coefficients import reference
from check_submit_choice import SCOPE as SUBMIT_SCOPE, OUTPUT_BUFFER, ALT_BUFFER
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    docs=[read(n) for n in ('submit-followup.json','fiplib-followup.json')]
    expected=read('provenance.json')['supplied_sha256']
    numeric=read('fiplib-coefficient-checks.json')
    assert numeric==reference(), 'FC coefficient fixture mismatch'
    submit=docs[0]['replay']
    assert submit['scope']==SUBMIT_SCOPE and submit['analysis_elf_sha256']==numeric['analysis_elf_sha256']
    assert len(submit['cases'])==2 and submit['stubs'] and submit['limitations']
    for case,selector,dest,buffer in zip(submit['cases'],(0,8),(0x801D0CC4,0x801D0BA0),(OUTPUT_BUFFER,ALT_BUFFER),strict=True):
        assert case['selector']==selector and int(case['selector_destination'],16)==dest
        assert int(case['path_output'],16)==OUTPUT_BUFFER and int(case['submitted_surface'],16)==buffer
        assert case['image_type']==8 and case['image_kind']==2
    for doc in docs:
        assert doc['input_sha256']==expected and doc['analysis_elf_sha256']==numeric['analysis_elf_sha256']
        assert list(witnesses(doc)) and doc['selected_functions']
        for f in doc['selected_functions']:
            assert f['candidate_end']-f['address']==f['size'] and f['size']>0
            assert not ((f['address']|f['candidate_end'])&3)
            assert len(f['sha256'])==64 and all(c in '0123456789abcdef' for c in f['sha256'])
            assert all(f['address']<=e['site']<f['candidate_end'] and not e['site']&3 for e in f['transfers'])
    if firmware is not None:
        from build_analysis_elf import PLAIN, DECODED
        from trace_q7 import trace
        assert hashlib.sha256(firmware).hexdigest()==expected and decoded is not None
        segments=[('E03',va,firmware[off:off+size],off) for off,va,size in PLAIN]
        segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,size in DECODED]
        count=0
        for doc in docs:
            count+=verify_words(doc,segments)
            actual=trace(firmware,[f['name'] for f in doc['selected_functions']],decoded)
            assert actual['functions']==doc['selected_functions'], 'HDR selector/FC trace mismatch'
        print(f'HDR selector/FC: {count} original word witnesses and function hashes/transfers reproduced')


if __name__=='__main__':
    verify()
    print('HDR selector/FC metadata: PASS')
