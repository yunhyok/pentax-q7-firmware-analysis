"""Verify native context selection separately from synthetic registry setup."""
from bisect import bisect_right
from hashlib import sha256
import json

from build_deep_report import read
from check_context_binding import validate_report
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA, recover
from verify_main_burn import extent_bytes
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    doc = read('context-binding.json')
    validate_report(doc['bounded_replay'])
    source = doc['source']
    assert sha256(json.dumps(doc['contracts'],sort_keys=True,separators=(',',':')).encode()).hexdigest() == 'd84d467460faeae741c52b423064a0ef0f4511109956a399137142f364ac8009'
    assert source['input_sha256'] == doc['input_sha256'] == SHA
    assert source['analysis_elf_sha256'] == doc['analysis_elf_sha256'] == ELF_SHA256
    assert sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest() == '519b42c745c63aa09bb97f13e12ecc666a881ef4ce3dc2931d6e5b2c10da148c'
    assert len(list(witnesses(source))) == 86 and len(source['selected_functions']) == 16
    if firmware is None:
        return
    assert decoded is not None and sha256(firmware).hexdigest() == SHA
    from build_analysis_elf import PLAIN, DECODED
    segments = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(source,segments) == 86
    _, symbols = recover(firmware)
    names = {}
    for symbol in symbols:
        names.setdefault(symbol['address'],[]).append(symbol['name'])
    addresses = sorted(names)
    for fn in source['selected_functions']:
        start = int(fn['address'],16)
        assert fn['names'] == names[start] and int(fn['candidate_end'],16) == addresses[bisect_right(addresses,start)]
        extent_bytes(fn,segments)
    print('Context binding:86 original words and16 explicit-address extents reproduced')


if __name__ == '__main__':
    verify()
    print('Context binding metadata: PASS')
