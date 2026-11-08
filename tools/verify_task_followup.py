"""Verify FC1 semantics and HDR task lifecycle evidence, optionally from firmware."""
import hashlib

from build_deep_report import read
from check_fc1_semantics import validate_report
from check_hdr_tasks import reference as task_reference
from check_ipu_completion import reference as completion_reference
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    docs=[read(n) for n in ('fc1-semantics.json','task-create-followup.json','task-completion-followup.json')]
    validate_report(docs[0]['replay'])
    assert docs[1]['replay']==task_reference(), 'HDR task replay mismatch'
    assert docs[2]['replay']==completion_reference(), 'IPU completion replay mismatch'
    expected=read('provenance.json')['supplied_sha256']
    for doc in docs:
        assert doc['input_sha256']==expected
        assert doc['analysis_elf_sha256']==completion_reference()['analysis_elf_sha256']
        assert list(witnesses(doc)) and doc['selected_functions']
        for f in doc['selected_functions']:
            assert f['candidate_end']-f['address']==f['size'] and f['size']>0
            assert not ((f['address']|f['candidate_end'])&3)
            assert len(f['sha256'])==64 and all(c in '0123456789abcdef' for c in f['sha256'])
            assert all(f['address']<=e['site']<f['candidate_end'] and not e['site']&3 for e in f['transfers'])
    comparison=read('task-comparison.json')
    assert len(comparison['comparisons'])==3 and len(comparison['source_blobs'])==6
    assert len(comparison['latest_public_main_sha_verified_via_gh'])==40
    if firmware is not None:
        from build_analysis_elf import PLAIN, DECODED
        from trace_q7 import trace
        assert hashlib.sha256(firmware).hexdigest()==expected and decoded is not None
        segments=[('E03',va,firmware[off:off+size],off) for off,va,size in PLAIN]
        segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,size in DECODED]
        count=0
        for doc in docs:
            count+=verify_words(doc,segments)
            assert trace(firmware,[f['name'] for f in doc['selected_functions']],decoded)['functions']==doc['selected_functions']
        print(f'FC1 semantics/HDR task lifecycle: {count} original words and function hashes/transfers reproduced')


if __name__=='__main__':
    verify()
    print('FC1 semantics/HDR task lifecycle metadata: PASS')
