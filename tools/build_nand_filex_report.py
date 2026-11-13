"""Build the NAND FileX report from its pinned JSON, without firmware or angr."""
from hashlib import sha256
from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_SHA256 = 'fddd47dea0a5cd639aa2bda20c137c47114c8851e8c8a5ff23a3440655375070'

CHECKPOINT_LABELS = (
    '매체 정보 생성자가 1을 반환(헤더 칸 일부는 기호값)',
    'AppFbLoader가 FileX 인수를 구성',
    '열린 매체 목록 포인터를 읽기 직전',
    '드라이버 연산 2(식별) 요청 직전',
    '식별값을 다시 넣은 뒤 헤더 함수 진입',
    '임시 버퍼 할당 후 연산 6 요청',
    '연산 6 상태 분기 직전(멈춤)',
)
ARGUMENT_MEANINGS = (
    '매체 구조체(<code>media_ptr</code>)', '매체 이름(<code>media_name</code>)',
    '드라이버 함수(<code>media_driver</code>)', '드라이버 정보(<code>driver_info_ptr</code>)',
    '캐시 메모리(<code>memory_ptr</code>)', '캐시 크기(<code>memory_size</code>)',
    '공개 목록에 없음. 특수값 비교에 쓰임',
)


def canonical(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def code(value):
    return '<code>' + escape(str(value)) + '</code>'


def main():
    data = json.loads((ROOT / 'analysis/nand-filex-checks.json').read_bytes())
    if canonical(data) != REPORT_SHA256:
        raise ValueError('complete FileX report differs')
    native = data['native_trace']
    static = data['static_evidence']
    standalone = json.loads((ROOT / 'analysis/nand-filex-source.json').read_bytes())
    if static != standalone:
        raise ValueError('standalone static FileX evidence differs')

    checkpoints = native['checkpoints']
    final = native['final']
    arguments = checkpoints[1]['filex_arguments']
    temp = native['temporary_allocations'][0]
    op6 = native['consumer_io'][1]
    # Fixed facts written in the template prose and diagrams.
    assert len(checkpoints) == len(CHECKPOINT_LABELS)
    assert [c['vex_events'] for c in checkpoints] == [86, 113, 115, 363, 406, 419, 422]
    assert arguments == ['0x24700000', '0x800ebd58', '0x8006444c', '0x2', '0x24701000', '0x4000', '0x1']
    assert checkpoints[1]['pc'] == '0x80067700' and checkpoints[-1]['pc'] == final['pc'] == '0x80055aac'
    assert native['geometry_from_synthetic_id'] == {
        'media_capacity_bf4': 1048576, 'media_flags_c18': '0x105', 'media_shift_c14': 8,
        'header_arguments': ['0x24700000', '0x1', '0x100', '0x1'], 'return_address': '0x80084114'}
    assert temp['address'] == final['temporary_header'] == '0x24800000' and temp['return_address'] == '0x80056700'
    assert final['registry_header'] == '0x24602000' and final['path_constraints_count'] == 0
    assert final['status_bits'] == 32 and final['status_ast_op'] == 'BVS' and not final['sat_queries_run']
    assert not final['branch_executed'] and not final['delay_slot_executed'] and final['admissible_examples_by_construction'] == [0, 1]
    assert native['consumer_io'][0]['supplied'].startswith('reused synthetic ID ecdc000100000000')
    assert native['producer_io'][2]['supplied'].startswith('symbolic header400 bytes except +14=0')

    counts = {segment: sum(row['segment'] == segment for row in static['ranges']) for segment in ('E03', 'E05')}
    names = {'0x8006444c': '_fx_nand_non_seq_read_driver'}
    values = {
        'checkpoint_rows': ''.join(
            f'<tr><th scope="row">{label}</th><td>{code(row["pc"])}</td><td class="n">{row["vex_events"]}</td></tr>'
            for label, row in zip(CHECKPOINT_LABELS, checkpoints)),
        'checkpoint_names': ''.join(f'<li>{label}: <code class="wrap">{escape(row["name"])}</code></li>'
            for label, row in zip(CHECKPOINT_LABELS, checkpoints)),
        'argument_rows': ''.join(
            f'<tr><th scope="row" class="n">{i}</th><td>{meaning}</td><td>{code(value)}'
            + (f' ({code(names[value])})' if value in names else '') + '</td></tr>'
            for i, (meaning, value) in enumerate(zip(ARGUMENT_MEANINGS, arguments), 1)),
        'temp_alloc_args': '[' + ','.join(temp['arguments']).replace('0x0', '0') + ']',
        'op6_args': '[' + ','.join(str(int(a, 16)) if int(a, 16) < 0x100 else a for a in op6['arguments']) + ']',
        'header_vex': str(checkpoints[4]['vex_events']),
        'op6_vex': str(checkpoints[5]['vex_events']),
        'stop_vex': str(checkpoints[6]['vex_events']),
        'e03_ranges': str(counts['E03']),
        'e05_ranges': str(counts['E05']),
        'firmware_sha': data['input_sha256'],
        'elf_sha': data['analysis_elf_sha256'],
        'native_sha': canonical(native),
        'static_sha': canonical(static),
    }
    assert values['temp_alloc_args'] == '[0,0x400,0,0x80063a88,0x6cb]'
    assert values['op6_args'] == '[1,0x24700000,6,0,1,0,0x70000be8,16]'
    page = (ROOT / 'analysis/nand-filex-template.html').read_text(encoding='utf-8')
    for key, value in values.items():
        page = page.replace('{{' + key + '}}', value)
    if '{{' in page:
        raise ValueError('unresolved HTML placeholder')
    output = ROOT / 'reports/nand-filex.html'
    output.parent.mkdir(exist_ok=True)
    output.write_text(page, encoding='utf-8', newline='\n')
    print('Built reports/nand-filex.html')


if __name__ == '__main__':
    main()
