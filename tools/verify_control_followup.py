"""Check HDR per-pass controls, submission metadata and original word witnesses."""
import hashlib

from build_deep_report import read
from check_fc1_controls import validate_report
from check_fc1_enable import reference
from check_hdr_passes import reference as hdr_reference
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    docs=[read(n) for n in ('control-followup.json','hdr-pass-followup.json','fc1-enable-checks.json')]
    expected=read('provenance.json')['supplied_sha256']
    validate_report(docs[0]['replay'])
    assert docs[2]['replay']==reference(), 'FC1 enable replay mismatch'
    assert docs[1]['replay']==hdr_reference(), 'HDR topology replay mismatch'
    hdr=docs[0]['fresh_hdr'];top=docs[1]['fresh_hdr']
    assert hdr['pass_count']==top['count']==4
    assert hdr['selected_range']==[top['start'],top['end_exclusive']]==[0,4]
    assert hdr['fiplib_phase']==top['fiplib_phase']==0
    assert hdr['final_index']==top['final_index']==3
    observed=docs[1]['replay']['result']
    assert [observed['processor_mode'],observed['cbc_mode']]==[top['processor_mode'],top['cbc_mode']]==[0,0]
    assert [observed['pass_count'],observed['start'],observed['end_exclusive']]==[4,0,4]
    assert observed['topology_locations']==top['topology_locations'] and observed['T']==top['T']
    assert [observed['S'],observed['D'],observed['Q']]==[hdr['input_1'],hdr['input_1072'],hdr['input_9']]==[0,0,0]
    passes=hdr['passes']
    assert len(passes)==4
    assert [p['topology_location'] for p in passes]==top['topology_locations']==[0,6,10,5]
    assert [p['pass_class'] for p in passes]==top['pass_classes']==['1x0','1x1','5x1','0x1']
    assert [p['topology_word'] for p in passes]==top['T']==[1,1,0,1]
    for i,p in enumerate(passes):
        assert p['pass_index']==i and p['final_pass']==(i==3)
        case=next(c for c in docs[0]['replay']['cases'] if c['case']==p['replay_case'])
        assert case['topology_word']==p['topology_word']
        assert case['expected']['payload_bypass_word']==p['expected_payload']['bypass_word']==[1,0,1,0][i]
        assert case['expected']['payload_flag_word']==p['expected_payload']['mode_1_flag_word']==0
        assert p['expected_direct_register_values']=={'0xb60000ec':[1,0,1,0][i], '0xb60000fc':0}
        binding=next(b for b in docs[0]['bindings'] if b['pass_class']==p['pass_class'])
        assert binding['vptr']==observed['pass_vtables'][i] and binding['top_controls']==observed['top_controls'][i]
    for doc in docs:
        assert doc['input_sha256']==expected and doc['analysis_elf_sha256']==reference()['analysis_elf_sha256']
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
            assert trace(firmware,[f['name'] for f in doc['selected_functions']],decoded)['functions']==doc['selected_functions']
        print(f'HDR controls/submit: {count} original words and function hashes/transfers reproduced')


if __name__=='__main__':
    verify()
    print('HDR controls/submit metadata: PASS')
