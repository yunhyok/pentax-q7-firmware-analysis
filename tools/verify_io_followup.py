"""Check header/hash/render metadata and reproduce original bytes, extents and resources."""
import hashlib
import json
import re
import struct
from build_deep_report import read
from check_burn_header import validate_report as validate_header
from check_burn_hash import validate_report as validate_hash
from check_hash_card import validate_report as validate_card
from check_colorspace_render import validate_report as validate_render
from check_burn_storage import BOOT_SHA256
from check_isp_registers import ELF_SHA256
from inspect_q7 import parse_elf
from q7_symbols import SHA
from verify_implementation import verify_boot_functions
from verify_routing import witnesses, verify_words


def resource_ranges(value):
    if isinstance(value, dict):
        if {'va', 'length_bytes', 'sha256'} <= value.keys():
            yield value
        for child in value.values():
            yield from resource_ranges(child)
    elif isinstance(value, list):
        for child in value:
            yield from resource_ranges(child)


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    header, card, render = (read(n) for n in ('header-hash.json', 'hash-card.json', 'colorspace-render.json'))
    validate_header(header['header_replay'])
    validate_hash(header['hash_replay'])
    validate_card(card['replay'])
    validate_render(render['replay'])
    canonical=json.dumps(header['hash_replay'],sort_keys=True,separators=(',',':')).encode()
    assert hashlib.sha256(canonical).hexdigest()==card['comparison']['canonical_replay_sha256']
    assert header['boot_elf_sha256'] == card['boot_elf_sha256'] == BOOT_SHA256
    assert render['analysis_elf_sha256'] == ELF_SHA256
    docs = ((header,101), (card,71), (render,139))
    for doc, count in docs:
        assert doc['input_sha256'] == SHA and len(list(witnesses(doc))) == count
    assert len(header['boot_selected_functions']) == 13 and len(header['boot_anonymous_ranges']) == 1
    assert len(card['selected_functions']) == 10 and len(render['selected_functions']) == 47
    functions = header['boot_selected_functions']+header['boot_anonymous_ranges']+card['selected_functions']+render['selected_functions']
    for f in functions:
        assert f['candidate_end']-f['address'] == f['size'] > 0
        assert re.fullmatch('[0-9a-f]{64}',f['sha256'])
        assert all(f['address'] <= t['site'] < f['candidate_end'] for t in f['transfers'])
    resources = list(resource_ranges(render))
    assert len(resources) == 38
    for r in resources:
        assert r['length_bytes'] > 0 and re.fullmatch('[0-9a-f]{64}',r['sha256'])
    if firmware is None:
        return
    assert hashlib.sha256(firmware).hexdigest() == SHA and decoded is not None
    boot, symbols = parse_elf(firmware, 0x200)
    assert boot['sha256_referenced_bytes'] == BOOT_SHA256
    boot_segments = [('E01', s['virtual_address'], firmware[s['file_offset']:s['file_offset']+s['file_size']], s['file_offset'])
                     for s in boot['segments'] if s['type'] == 1]
    assert verify_words(header,boot_segments) == 101 and verify_words(card,boot_segments) == 71
    typed = header['boot_selected_functions']+[f for f in card['selected_functions'] if 'section_index' in f]
    assert len(typed) == 21
    verify_boot_functions(firmware,boot,symbols,typed)
    from trace_q7 import transfer, trace
    labels = {}
    for s in symbols:
        if s['name']:
            labels.setdefault(s['value'],[]).append(s['name'])
    anonymous = header['boot_anonymous_ranges']+[f for f in card['selected_functions'] if 'section_index' not in f]
    for f in anonymous:
        off = int(f['original_file_offset'],16)
        assert any(base <= f['address'] < f['candidate_end'] <= base+len(data) and off == fileoff+f['address']-base
                   for _,base,data,fileoff in boot_segments)
        body = firmware[off:off+f['size']]
        assert hashlib.sha256(body).hexdigest() == f['sha256']
        edges=[]
        for i,(raw,) in enumerate(struct.iter_unpack('<I',body)):
            pc=f['address']+4*i
            edge=transfer(raw,pc)
            if edge:
                kind,target=edge
                if kind=='jump' and f['address'] <= target < f['candidate_end']:
                    continue
                edges.append(dict(site=pc,word=f'{raw:08x}',kind=kind,target=target,target_names=labels.get(target,[])))
        assert edges == f['transfers']
    from build_analysis_elf import PLAIN, DECODED
    segments=[('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(render,segments) == 139
    assert trace(firmware,[f['name'] for f in render['selected_functions']],decoded)['functions'] == render['selected_functions']
    for r in resources:
        address,size=int(r['va'],16),r['length_bytes']
        matches=[(name,base,data,off) for name,base,data,off in segments if base <= address < address+size <= base+len(data)]
        assert len(matches)==1
        name,base,data,off=matches[0]
        field='decoded_offset' if off is None else 'original_file_offset'
        assert name==r['segment'] and int(r[field],16)==address-base+(off or 0)
        assert hashlib.sha256(data[address-base:address-base+size]).hexdigest()==r['sha256']
    print('Header/hash/card/render: 311 original words,21 typed/3 anonymous E01 records,47 main functions,38 resource ranges reproduced')


if __name__=='__main__':
    verify()
    print('Header/hash and drawing metadata: PASS')
