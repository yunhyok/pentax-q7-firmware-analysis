"""Verify follow-up metadata and original instruction/data-word witnesses."""
import json
import struct
from pathlib import Path

from check_isp_registers import validate_report

ROOT = Path(__file__).resolve().parents[1]


def witnesses(value):
    if isinstance(value, dict):
        if 'va' in value and 'u32le_word' in value:
            yield value
        for child in value.values():
            yield from witnesses(child)
    elif isinstance(value, list):
        for child in value:
            yield from witnesses(child)


def verify_words(document, segments):
    count = 0
    for item in witnesses(document):
        address, expected = int(item['va'],16), int(item['u32le_word'],16)
        assert address % 4 == 0 and 0 <= expected < 2**32
        for name, base, body, file_offset in segments:
            if base <= address <= base+len(body)-4:
                assert struct.unpack_from('<I',body,address-base)[0] == expected, f'word mismatch: {address:#x}'
                assert item['segment'] == name, f'segment mismatch: {address:#x}'
                field = 'original_file_offset' if file_offset is not None else 'decoded_offset'
                assert int(item[field],16) == address-base+(file_offset or 0), f'coordinate mismatch: {address:#x}'
                count += 1
                break
        else:
            raise AssertionError(f'unmapped word witness: {address:#x}')
    return count


def verify(firmware=None, decoded=None):
    def read(name): return json.loads((ROOT/'analysis'/name).read_text(encoding='utf-8'))
    lens, isp, replay, output = (read(n) for n in ('lens-routing.json','isp-routing.json','isp-register-checks.json','output-routing.json'))
    expected_hash = read('provenance.json')['supplied_sha256']
    assert lens['input_sha256'] == isp['input_sha256'] == expected_hash
    assert lens['analysis_elf_sha256'] == isp['analysis_elf_sha256'] == replay['analysis_elf_sha256']
    assert output['firmware']['source_original_sha256'] == expected_hash
    assert output['firmware']['synthetic_analysis_image_sha256'] == isp['analysis_elf_sha256']
    validate_report(replay)
    assert lens['bounded_replay']['binding_case'] == dict(start='0x8037e13c',stop='0x8040cc6c',pointer='0x80c17e00',value='0x8040a008')
    assert len(lens['bounded_replay']['cases']) == 4
    for mode, message, command in [(0,6,4),(1,8,6),(2,7,3),(3,2,4)]:
        case = lens['bounded_replay']['cases'][mode]
        assert case['mode'] == mode and case['queue_message'] == message
        assert case['recipient'] == '0x8040a008' and case['callback_arguments'] == [0x6003c,0]
        assert case['lens_communication_arguments'] == [0,1,2,command]
    functions = {f['address']:f for f in isp['selected_functions']}
    assert len(functions) == isp['decompilation']['count'] == len(isp['decompilation']['functions']) == 90
    for f in isp['decompilation']['functions']:
        other = functions[f['address']]
        assert f['completed'] and not f['timed_out']
        assert f['name'] == other['name'] and f['body_bytes'] == other['size']
    assert len(list(witnesses(lens))) >= 140 and len(list(witnesses(isp))) >= 50
    assert len(list(witnesses(output))) >= 20
    assert output['filesystem_boundary']['status'] == 'conditionally_connected'
    for f in output['selected_functions']:
        assert f['candidate_end'] - f['address'] == f['size']
        assert len(f['sha256']) == 64 and all(c in '0123456789abcdef' for c in f['sha256'])
        assert all(f['address'] <= e['site'] < f['candidate_end'] for e in f['transfers'])
    if firmware is not None:
        from build_analysis_elf import PLAIN, DECODED
        from trace_q7 import trace
        assert decoded is not None
        segments = [('E03',va,firmware[off:off+size],off) for off,va,size in PLAIN]
        segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,size in DECODED]
        total = sum(verify_words(document,segments) for document in (lens,isp,output))
        actual = trace(firmware,[f['name'] for f in isp['selected_functions']],decoded)
        assert actual['functions'] == isp['selected_functions'], 'ISP function evidence mismatch'
        actual = trace(firmware,[f['name'] for f in output['selected_functions']],decoded)
        assert actual['functions'] == output['selected_functions'], 'Output function evidence mismatch'
        actual = trace(firmware,[f['name'] for f in lens['selected_functions']],decoded)
        for f,recorded in zip(actual['functions'],lens['selected_functions'],strict=True):
            assert f['address'] == int(recorded['entry_va'],16)
            assert f['candidate_end'] == int(recorded['candidate_end_va'],16)
        print(f'Lens/ISP/output: {total} original word witnesses, 90 ISP + {len(output["selected_functions"])} output ranges/hashes/transfers and lens extents reproduced')


if __name__ == '__main__':
    verify()
    print('Routing metadata and replay reference fixtures: PASS')
