"""Validate Color Space fixtures and reproduce selected original-code evidence."""
import hashlib
import re
from build_deep_report import read
from check_colorspace_ui import validate_report
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA
from verify_routing import witnesses, verify_words


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    ui = read('colorspace-ui.json')
    validate_report(ui['replay'])
    assert ui['input_sha256'] == SHA and ui['analysis_elf_sha256'] == ELF_SHA256
    assert len(ui['selected_functions']) == 56
    assert len(list(witnesses(ui))) == 180
    assert sum(len(c['steps']) for c in ui['replay']['cases']) == 28
    for f in ui['selected_functions']:
        assert f['candidate_end'] - f['address'] == f['size'] > 0
        assert re.fullmatch(r'[0-9a-f]{64}', f['sha256'])
    if firmware is None:
        return
    from build_analysis_elf import PLAIN, DECODED
    from trace_q7 import trace
    assert hashlib.sha256(firmware).hexdigest() == SHA and decoded is not None
    segments = [('E03', va, firmware[o:o+n], o) for o, va, n in PLAIN]
    segments += [(name[:-4], va, decoded[name[:-4]], None) for name, va, _ in DECODED]
    assert verify_words(ui, segments) == 180
    assert trace(firmware, [f['name'] for f in ui['selected_functions']], decoded)['functions'] == ui['selected_functions']
    print('Color Space UI: 180 original words and 56 function hashes/transfers reproduced')


if __name__ == '__main__':
    verify()
    print('Color Space UI metadata: PASS')
