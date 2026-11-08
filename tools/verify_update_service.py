"""Verify the MAIN updater bridge without confusing E01's same-named routines."""
import hashlib
import json
from build_deep_report import read
from check_update_service import validate_report
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA
from trace_q7 import trace
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    doc = read('update-service.json')
    validate_report(doc['bounded_replay'])
    assert doc['input_sha256'] == SHA and doc['analysis_elf_sha256'] == ELF_SHA256
    keys = ('selected_functions','evidence','modeled_boundaries','prior_E01','comparison','resource_ranges')
    assert hashlib.sha256(json.dumps([doc[k] for k in keys],sort_keys=True,separators=(',',':')).encode()).hexdigest() == '433ffcb517258044a2c6e59271cf336cf54a49d0567333971ab85a303262ad63'
    assert len(list(witnesses(doc))) == 98 and len(doc['selected_functions']) == 12
    prior = read('rebuild-evidence.json')['boot_dispatch']
    assert prior['function'] == doc['prior_E01']['get_handle']
    assert prior['callback_field'] == 'handle+' + doc['prior_E01']['callback_field']
    assert prior['actual_selected_callback'].split()[0] == doc['prior_E01']['selected_callback']
    if firmware is None:
        return
    assert decoded is not None and hashlib.sha256(firmware).hexdigest() == SHA
    from build_analysis_elf import PLAIN, DECODED
    segments = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(doc,segments) == 98
    assert trace(firmware,[f['name'] for f in doc['selected_functions']],decoded)['functions'] == doc['selected_functions']
    for record in doc['resource_ranges']:
        start, size = int(record['va'],16), record['length_bytes']
        name,base,data,offset = next(s for s in segments if s[1] <= start < start+size <= s[1]+len(s[2]))
        assert offset is None and name == record['segment']
        assert start-base == int(record['decoded_offset'],16)
        assert hashlib.sha256(data[start-base:start-base+size]).hexdigest() == record['sha256']
    header = firmware[0x100000:0x1000c0]
    assert hashlib.sha256(header).hexdigest() == doc['bounded_replay']['header_sha256']
    print('MAIN update service:98 original words,12 functions,2 path resources and E01 distinction reproduced')


if __name__ == '__main__':
    verify()
    print('MAIN update service metadata: PASS')
