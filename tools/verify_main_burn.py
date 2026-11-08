"""Verify distinct MAIN/E01 provenance for the bounded MAIN Burn prefixes."""
from bisect import bisect_right
from hashlib import sha256
import json
import struct

from build_deep_report import read
from check_main_burn import validate_report
from check_burn_storage import BOOT_SHA256
from check_isp_registers import ELF_SHA256
from inspect_q7 import parse_elf
from q7_symbols import SHA, recover
from verify_routing import verify_words, witnesses


def extent_bytes(record, segments):
    start, end = int(record['address'],16), int(record['candidate_end'],16)
    assert end-start == record['size'] and (start | end) & 3 == 0
    name,base,data,offset = next(s for s in segments if s[1] <= start < end <= s[1]+len(s[2]))
    field = 'decoded_offset' if offset is None else 'original_file_offset'
    assert record['segment'] == name and int(record[field],16) == start-base+(offset or 0)
    body = data[start-base:end-base]
    assert sha256(body).hexdigest() == record['sha256']
    return body


def verify(firmware=None, decoded=None):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    doc = read('main-burn-prefix.json')
    validate_report(doc['bounded_replay'])
    source = doc['source']
    assert doc['input_sha256'] == SHA and doc['analysis_elf_sha256'] == ELF_SHA256
    assert sha256(json.dumps(doc['call_contract'],sort_keys=True,separators=(',',':')).encode()).hexdigest() == 'b5bac176126de6a5eaa6fad0ddd32129a3d777f4099770d030695657be0c191a'
    assert source['input_sha256'] == SHA and source['analysis_elf_sha256'] == ELF_SHA256
    assert source['boot_elf_sha256'] == BOOT_SHA256
    assert sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest() == '003faee66fd00077095b7314c0b171e8542bd6a437ecba917d06f6ae7734c226'
    assert len(list(witnesses(source['main_words']))) == 98
    assert len(list(witnesses(source['e01_words']))) == 11
    assert len(source['main_functions']) == 24 and len(source['boot_functions']) == 1
    if firmware is None:
        return
    assert decoded is not None and sha256(firmware).hexdigest() == SHA
    for key,field in (('update_header','original_file_offset'),('installed_header','borrowed_package_offset')):
        resource = doc['bounded_replay']['fixture'][key]
        start = int(resource[field],16)
        assert sha256(firmware[start:start+resource['size']]).hexdigest() == resource['sha256']
    from build_analysis_elf import PLAIN, DECODED
    main = [('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    main += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    boot, typed = parse_elf(firmware,0x200)
    assert boot['sha256_referenced_bytes'] == BOOT_SHA256
    e01 = [('E01',s['virtual_address'],firmware[s['file_offset']:s['file_offset']+s['file_size']],s['file_offset'])
           for s in boot['segments'] if s['type'] == 1 and s['file_size']]
    assert verify_words(source['main_words'],main) == 98 and verify_words(source['e01_words'],e01) == 11
    _, symbols = recover(firmware)
    names = {}
    for symbol in symbols:
        names.setdefault(symbol['address'],[]).append(symbol['name'])
    addresses = sorted(names)
    for fn in source['main_functions']:
        start = int(fn['address'],16)
        assert fn['names'] == names[start] and int(fn['candidate_end'],16) == addresses[bisect_right(addresses,start)]
        extent_bytes(fn,main)
    fn, = source['boot_functions']
    original, = [s for s in typed if s['name'] == fn['names'][0] and s['value'] == int(fn['address'],16) and s['type'] == 2]
    assert original['size'] == fn['size']
    old = extent_bytes(fn,e01)
    current, = [fn for fn in source['main_functions'] if fn['address'] == '0x805dd7b8']
    pairs = list(zip(struct.iter_unpack('<I',extent_bytes(current,main)),struct.iter_unpack('<I',old),strict=True))
    comparison = source['comparison']
    assert len(pairs) == comparison['words'] == 2760
    assert sum(a == b for a,b in pairs) == comparison['byte_identical_words'] == 2166
    assert sum(a[0] >> 26 == b[0] >> 26 for a,b in pairs) == comparison['same_primary_opcode'] == 2760
    print('MAIN Burn prefix:98 MAIN/11 E01 words,24 MAIN/1 typed E01 extents and structural comparison reproduced')


if __name__ == '__main__':
    verify()
    print('MAIN Burn prefix metadata: PASS')
