"""Validate buffer/pass evidence and optionally reproduce it from the original BIN."""
import hashlib
from pathlib import Path

from build_deep_report import read
from check_color_handoff import reference
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    docs=[read(n) for n in ('buffer-followup.json','pass-followup.json')]
    expected=read('provenance.json')['supplied_sha256']
    replay=read('color-handoff-checks.json')
    assert replay==reference(), 'color handoff replay fixture mismatch'
    for doc in docs:
        assert doc['input_sha256']==expected
        assert doc['analysis_elf_sha256']==replay['analysis_elf_sha256']
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
            assert actual['functions']==doc['selected_functions'], 'follow-up function trace mismatch'
        for table in docs[1]['pass_selection']['filter_tables'].values():
            offset=int(table['table_va'],16)-0x8012DA80
            raw=decoded['E04'][offset:offset+table['inspected_ids']]
            assert [i for i,v in enumerate(raw) if v] == table['nonzero_ids']
        dirty_table=0x80359448-0x8012DA80
        assert decoded['E04'][dirty_table+14:dirty_table+16]==b'\0\1'
        print(f'Pixel follow-up: {count} original word witnesses, function hashes/transfers and pass tables reproduced')


if __name__=='__main__':
    verify()
    print('Pixel follow-up metadata: PASS')
