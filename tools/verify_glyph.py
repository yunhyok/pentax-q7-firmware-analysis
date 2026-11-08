"""Verify exact font provenance, text linkage and address-selected code ranges."""
from bisect import bisect_right
from hashlib import sha256
import json
import struct

from build_deep_report import read
from check_colorspace_glyph import read_font, validate_report
from check_isp_registers import ELF_SHA256
from q7_symbols import SHA, recover
from trace_q7 import transfer
from verify_routing import verify_words, witnesses


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    doc = read('colorspace-glyph.json')
    validate_report(doc['bounded_replay'])
    assert doc['input_sha256'] == SHA and doc['analysis_elf_sha256'] == ELF_SHA256
    records = [doc[k] for k in ('selected_functions','evidence','input_reference','comparison')]
    assert sha256(json.dumps(records,sort_keys=True,separators=(',',':')).encode()).hexdigest() == '04008a2b4261ca1e52dd36de8d1758a15dad7aa8c066a1bf0491db905843a514'
    assert len(list(witnesses(doc))) == 62 and len(doc['selected_functions']) == 10
    prior = read('colorspace-render.json')
    source = doc['input_reference']
    label, = [r for r in prior['labels'] if r['widget'] == source['widget']]
    descriptor, = [r for r in label['descriptors'] if r['locale'] == source['locale']]
    assert descriptor['lines'] == [source['line']]
    row, = [r for r in prior['replay']['refresh_cases'][0]['text'] if r['widget'] == int(source['widget'],16)]
    case = doc['bounded_replay']['cases'][1]
    assert row['xy'] == source['xy'] == doc['bounded_replay']['context']['origin']
    assert row['glyph_units'] == len(source['units']) == 4
    assert case['units'] == source['units']
    assert row['staged_sha256'] == source['line']['sha256'] == case['text_draw_call']['text_sha256']
    if firmware is None:
        return
    read_font(firmware)
    assert decoded is not None
    from build_analysis_elf import PLAIN, DECODED
    segments = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(doc,segments) == 62
    _, symbols = recover(firmware)
    names = {}
    for symbol in symbols:
        names.setdefault(symbol['address'],[]).append(symbol['name'])
    addresses = sorted(names)
    for fn in doc['selected_functions']:
        start,end = fn['address'],fn['candidate_end']
        assert fn['name'] in names[start] and end == addresses[bisect_right(addresses,start)]
        assert end-start == fn['size'] and (start | end) & 3 == 0
        segment,base,data,offset = next(s for s in segments if s[1] <= start < end <= s[1]+len(s[2]))
        assert segment == fn['segment'] and offset is None and fn['decoded_offset'] == start-base
        body = data[start-base:end-base]
        assert sha256(body).hexdigest() == fn['sha256']
        edges = []
        for position,(word,) in enumerate(struct.iter_unpack('<I',body)):
            pc = start+position*4
            item = transfer(word,pc)
            if item:
                kind,target = item
                if kind == 'jump' and start <= target < end:
                    continue
                edges.append(dict(site=pc,word=f'{word:08x}',kind=kind,target=target,target_names=names.get(target,[])))
        assert edges == fn['transfers']
    line = source['line']
    raw = decoded[line['segment']][int(line['decoded_offset'],16):int(line['decoded_offset'],16)+line['length_bytes']]
    assert raw == struct.pack('<4H',*source['units']) and sha256(raw).hexdigest() == line['sha256']
    print('Glyph:62 original words,10 explicit-address ranges/transfers,FAT font chain and prior sRGB text linkage reproduced')


def verify_attributes(firmware=None, decoded=None):
    from check_colorspace_attributes import validate_report as validate_attributes
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    doc = read('colorspace-attributes.json')
    validate_attributes(doc['bounded_replay'])
    keys = ('selected_functions','evidence','input_reference','attribute_dispatch','scale_oracle')
    assert sha256(json.dumps([doc[k] for k in keys],sort_keys=True,separators=(',',':')).encode()).hexdigest() == 'c94edc98ce21043b0ba7b83adbfb78001f7629052000ab262812af600c0712ba'
    assert doc['input_sha256'] == SHA and doc['analysis_elf_sha256'] == ELF_SHA256
    assert len(list(witnesses(doc))) == 71 and len(doc['selected_functions']) == 12
    source = read('colorspace-glyph.json')['input_reference']
    assert doc['input_reference']['widget'] == source['widget']
    assert doc['input_reference']['staged_units_sha256'] == source['line']['sha256']
    assert doc['bounded_replay']['units'] == source['units']
    prior = read('colorspace-render.json')['replay']['refresh_cases']
    assert sha256(json.dumps(prior,sort_keys=True,separators=(',',':')).encode()).hexdigest() == doc['bounded_replay']['refresh']['prior_refresh_sha256']
    if firmware is None:
        return
    read_font(firmware)
    assert decoded is not None
    from build_analysis_elf import PLAIN, DECODED
    segments = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    assert verify_words(doc,segments) == 71
    _, symbols = recover(firmware)
    names = {}
    for symbol in symbols:
        names.setdefault(symbol['address'],[]).append(symbol['name'])
    addresses = sorted(names)
    for fn in doc['selected_functions']:
        start,end = fn['address'],fn['candidate_end']
        assert fn['names'] == names[start] and end == addresses[bisect_right(addresses,start)]
        assert end-start == fn['size'] and (start | end) & 3 == 0
        segment,base,data,offset = next(s for s in segments if s[1] <= start < end <= s[1]+len(s[2]))
        assert segment == fn['segment'] and offset is None and fn['decoded_offset'] == start-base
        assert sha256(data[start-base:end-base]).hexdigest() == fn['sha256']
    line = source['line']
    start = int(line['decoded_offset'],16)
    raw = decoded[line['segment']][start:start+line['length_bytes']]
    assert raw == struct.pack('<4H',*source['units']) and sha256(raw).hexdigest() == line['sha256']
    print('Font attributes:71 original words,12 explicit extents,prior refresh and text linkage reproduced')


if __name__ == '__main__':
    verify()
    print('Glyph metadata: PASS')
