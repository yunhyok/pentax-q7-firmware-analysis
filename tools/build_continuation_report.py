"""Render the NAND retry and finalization report (burn-continuation-report.html).

The prose and the diagrams live in analysis/continuation-template.html. This builder supplies the
tables and counts from analysis/burn-continuation.json and analysis/burn-finalization.json, and
checks that the values quoted in the static prose and diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

# name -> (Korean label, what the fixture supplies, expected fixture settings)
CASES = {
    'nominal-prefix': ('처음 세 블록이 모두 성공', '기록 결과를 모두 성공으로 응답', (False, 0, 1, [0, 0])),
    'program-retry': ('첫 기록이 실패', '첫 기록 결과만 실패로 응답', (True, 0, 1, [0, 0])),
    'marker-error-retry': ('첫 기록이 실패하고 불량 표시도 오류', '첫 기록은 실패, 연산 7에는 오류 7을 응답', (True, 7, 1, [0, 0])),
    'spare-bad-block': ('블록 1이 불량으로 표시돼 있음', '블록 1의 예비 영역 <code>+5</code>를 0으로 응답', (False, 0, 1, [1, 2])),
    'next-card-read-error': ('다음 청크의 카드 읽기가 실패', '카드 읽기 함수의 반환값을 0으로 응답', (False, 0, 0, [0, 0])),
    'candidate-exhaustion': ('첫 기록 실패 뒤 쓸 수 있는 블록이 없음', '첫 기록은 실패, 블록 1~639는 불량으로 응답', (True, 0, 1, [1, 640])),
    'main-payload-to-metadata': ('135개 청크가 모두 성공', '기록 결과를 모두 성공으로 응답', (False, 0, 1, [0, 0])),
}
STOPS = {'0x80011da8': '다음 기록 함수 진입에서 시험을 멈춤', '0x8008249c': '확장 헤더 기록 요청에서 시험을 멈춤'}
TERMINAL = {
    'extended-write-error': ('확장 헤더 기록이 오류', '① 확장 헤더 기록'),
    'primary-read-error': ('블록 0 읽기가 오류', '② 블록 0 읽기'),
    'primary-write-error': ('블록 0 다시 쓰기가 오류', '④ 블록 0 다시 쓰기'),
    'all-success': ('네 요청이 모두 성공', '없음'),
}
OPERATIONS = {'0x4': '4 (읽기)', '0x5': '5 (기록)', '0x8': '8 (지우기)'}
MODELS = {
    'cache maintenance no-op': '캐시 정리 요청: 아무 일도 하지 않음',
    'free no-op': '메모리 해제: 아무 일도 하지 않음',
    'diagnostic log no-op': '진단 로그: 아무 일도 하지 않음',
    'zeroed synthetic heap, continuing the prefix allocation cursor': '메모리 할당: 0으로 채운 합성 메모리를 내줌 (앞 단계의 할당 위치에서 이어 감)',
    'read the next complete original package chunk or return fixture failure without advancing':
        '카드 읽기 함수: 원본 패키지의 다음 청크 전체를 건네거나, 위치를 옮기지 않고 시험용 실패값을 반환',
    'op 6 supplies synthetic spare bytes; op 7 returns fixture status and retains successful spare writes':
        '저장장치 요청: 연산 6에는 합성 예비 바이트를 건넴. 연산 7에는 시험용 상태값을 반환하고, 성공한 예비 영역 쓰기는 보관',
    'aggregate result 1 on success or 0 plus x in the map on failure; no device or readback execution':
        '기록·비교 함수: 성공이면 1을, 실패면 0을 반환하고 블록 맵에 <code>x</code>를 적음. 장치 동작과 다시 읽기는 실행하지 않음',
    'Provide one zero-initialized synthetic block buffer.': '메모리 할당: 0으로 채운 블록 크기의 합성 버퍼 하나를 내줌',
    'Record the requested free arguments and return without changing synthetic RAM.': '메모리 해제: 요청 인수를 기록하고 메모리는 바꾸지 않음',
    'Diagnostic logging no-op carried from the original preflight replay.': '진단 로그: 아무 일도 하지 않음 (앞 단계와 같음)',
    'Cache-maintenance no-op carried from the original preflight replay.': '캐시 정리 요청: 아무 일도 하지 않음 (앞 단계와 같음)',
    'Return fixture status for the four recognized requests. The block-zero read supplies the full data and spare bytes captured before its earlier aggregate program. No device I/O occurs.':
        '저장장치 요청: 알려진 네 요청에 시험용 상태값을 반환. 블록 0 읽기에는 앞서 블록 0 기록 함수로 넘어갔던 데이터 전체와 예비 바이트를 건넴. 장치 입출력은 없음',
}
FUNCTIONS = {
    'spare read wrapper': '예비 영역 읽기 래퍼',
    'protection and spare metadata predicate': '보호·예비 영역 판정',
    'bad-block marker': '불량 표시 함수',
    'bad-block check': '불량 판정 함수',
    'program/readback helper modeled in continuation': '기록·비교 함수 (이 문서에서는 모델)',
    'sCardFunc ready callback': '카드 함수 표의 준비 함수',
}
WORD_ROLES = {
    'original helper contract used by aggregate model': '모델이 따르는 기록·비교 함수의 계약',
    'main program call and conditional branch': '기록 함수 호출과 결과 분기',
    'success advances logical/source state': '성공했을 때 논리 블록과 입력 위치를 진행',
    'failure invokes native marker and retries with incremented physical index': '실패했을 때 불량 표시 뒤 물리 블록 번호를 늘려 재시도',
    'marker layout, op 7 and native return': '불량 표시의 예비 영역 값, 연산 7, 반환값',
    'candidate spare decode and skip': '후보 블록의 예비 영역 해석과 건너뛰기',
    'user-area rejection and candidate exhaustion': '사용자 영역 제외와 후보 소진',
    'remaining section count, next card request, and failure result': '섹션의 남은 양, 다음 카드 요청, 실패 결과',
    'later direct four-sector program request': '뒤따르는 4섹터 기록 요청',
    'Section2 first512-byte preservation, main-buffer FF fill and later mutated-header submission': '섹션 2 첫 512바이트의 보관, 주 버퍼의 FF 채움, 고친 헤더의 제출',
    'extended-header op 5 and result dispatch': '확장 헤더의 연산 5와 결과 분기',
    'early error cleanup and return': '오류가 났을 때의 정리와 반환',
    'primary buffer allocation, op 4 read and failure': '블록 0용 버퍼 할당, 연산 4 읽기와 실패 분기',
    'extended-header location and primary op 8 erase': '확장 헤더 위치의 기록과 블록 0의 연산 8',
    'full-block primary op 5 and error branch': '블록 0 전체의 연산 5와 오류 분기',
    'cleanup, native ready callback and terminal status': '정리, 준비 함수 호출, 마지막 반환값',
}


def n(value):
    return f'{value:,}'


def code(value):
    return f'<code>{esc(value)}</code>'


def build_burn():
    data = read('burn-continuation.json')
    terminal = read('burn-finalization.json')
    replay, final = data['bounded_replay'], terminal['bounded_replay']
    cases = {c['name']: c for c in replay['cases']}
    ends = {c['name']: c for c in final['cases']}
    rebuilt = data['source_reconstruction']

    # Values that the template quotes as fixed text in prose and diagrams.
    assert list(cases) == list(CASES) and list(ends) == list(TERMINAL)
    for f in data['fixture_configuration']:
        assert (f['fail_first_aggregate'], f['op7_status'], f['card_callback_status'], f['spare_bad_blocks_half_open']) == CASES[f['name']][2]
    prefix = replay['prefix']
    assert (prefix['synthetic_blocks'], prefix['sectors_per_block'], prefix['sector_bytes']) == (1024, 256, 512)
    assert prefix['schedule']['total_modeled_requests'] == 3331
    assert (prefix['installed_header']['user_start_block'], prefix['installed_header']['user_block_count']) == (640, 384)
    retry = cases['program-retry']
    first, second = retry['program_samples'][:2]
    assert (first['block'], first['logical_block'], first['aggregate_result']) == (0, 0, 0)
    assert (second['block'], second['logical_block'], second['aggregate_result']) == (1, 0, 1)
    assert first['source_sha256'] == second['source_sha256'] and first['next_card_offset'] == second['next_card_offset']
    assert [m['spare_status_bytes'] for m in retry['markers']] == [[0, 240], [0, 240]]
    assert [m['status'] for m in cases['marker-error-retry']['markers']] == [7]
    assert [(s['block'], s['logical_block']) for s in cases['spare-bad-block']['program_samples']] == [(0, 0), (2, 1)]
    exhausted = cases['candidate-exhaustion']
    assert (exhausted['protection_skip_count'], exhausted['aggregate_program_calls'], exhausted['return_value']) == (384, 1, 1)
    assert exhausted['map_counts'] == {'B': 639, 'P': 384, 'x': 1}
    assert exhausted['control_sites'][-1] == {'site': '0x80014890', 'block': 1024}
    assert cases['next-card-read-error']['return_value'] == 1
    full = cases['main-payload-to-metadata']
    assert (full['aggregate_program_calls'], full['modeled_card_reads'], full['program_sections']) == (135, 134, {'1': 10, '2': 125})
    assert full['source_changes'] == [[0, 281], [10, 512]] and full['map_counts'] == {'P': 384, '_': 640}
    assert full['pending_storage'] == {'return_address': '0x8001437c',
                                       'arguments': ['0x10000000', '0x5', '0xa00', '0x4', '0x11000c10', '0x0', '0x0']}
    assert 0xA00 == 10 * prefix['sectors_per_block']
    assert (rebuilt['main_changed_bytes'], rebuilt['direct_first512_changed_bytes'], rebuilt['package_chunk_offset']) == (512, 132, '0x2400c0')
    assert rebuilt['direct_sha256'] == full['pending_storage_data_sha256']
    done = ends['all-success']
    assert [(r['arguments'][1], r['arguments'][2], r['arguments'][3]) for r in done['requests']] == [
        ('0x5', '0xa00', '0x4'), ('0x4', '0x0', '0x100'), ('0x8', '0x0', '0x1'), ('0x5', '0x0', '0x100')]
    assert done['requests'][3]['data_changes_from_aggregate_block_zero'] == [[924, 255, 10], [925, 255, 0], [926, 255, 0], [927, 255, 0]]
    assert 924 == 0x39C
    assert (done['native_ready_callers'], done['return_value']) == (['0x80014d80'], 0)
    assert all(ends[name]['return_value'] == 1 and not ends[name]['native_ready_callers'] for name in TERMINAL if name != 'all-success')
    assert [len(ends[name]['requests']) for name in TERMINAL] == [1, 2, 4, 4]
    ready = terminal['selected_functions'][1]
    assert (ready['address'], ready['size']) == (0x80019390, 8)
    words, words_final = len(list(witnesses(data))), len(list(witnesses(terminal)))
    assert (words, words_final) == (116, 63)
    assert (len(data['selected_functions']), len(terminal['selected_functions'])) == (9, 2)

    def attempts(case):
        if case['aggregate_program_calls'] > len(case['program_samples']):
            return f'{case["aggregate_program_calls"]}회 모두 성공 (섹션 1에서 {case["program_sections"]["1"]}회, 섹션 2에서 {case["program_sections"]["2"]}회)'
        return ', '.join(f'물리 {s["block"]} ← 논리 {s["logical_block"]}: {"성공" if s["aggregate_result"] else "실패"}'
                         for s in case['program_samples'])

    def outcome(case):
        if case['return_value'] is None:
            return STOPS[case['stop']]
        return f'<code>BurnNand</code>가 {case["return_value"]}을 반환'

    v = {}
    v['rows'] = ''.join(
        f'<tr><th scope="row">{CASES[name][0]} {code(name)}</th><td>{CASES[name][1]}</td><td>{attempts(c)}</td>'
        f'<td class="n">{c["modeled_card_reads"]}</td><td class="n">{c["protection_skip_count"]}</td>'
        f'<td>{code(c["map_first_four"])}</td><td>{outcome(c)}</td></tr>' for name, c in cases.items())
    v['io_rows'] = ''.join(
        f'<tr><th scope="row">{code(name)}</th><td class="n">{n(c["io_counts"].get("6", 0))}</td><td class="n">{c["io_counts"].get("7", 0)}</td>'
        f'<td>{", ".join(f"{k} {n(count)}개" for k, count in c["map_counts"].items())}</td>'
        f'<td>{code(c["next_card_offset"])}</td><td>{code(c["aggregate_program_sha256"][:16] + "…")}</td></tr>'
        for name, c in cases.items())
    v['terminal_rows'] = ''.join(
        f'<tr><th scope="row">{TERMINAL[name][0]} {code(name)}</th><td>{TERMINAL[name][1]}</td><td class="n">{len(c["requests"])}</td>'
        f'<td class="n">{len(c["native_ready_callers"])}</td><td class="n">{len(c["free_calls"])}</td><td class="n">{c["return_value"]}</td></tr>'
        for name, c in ends.items())
    v['request_rows'] = ''.join(
        f'<tr><th scope="row">{"①②③④"[i]}</th><td>{OPERATIONS[r["arguments"][1]]}</td><td>{code(r["arguments"][2])}</td>'
        f'<td class="n">{int(r["arguments"][3], 16)}</td><td>{"16바이트" if r["arguments"][6] != "0x0" else "없음"}</td>'
        f'<td>{code(r["return_address"])}</td><td>{code(r["data_sha256"][:16] + "…") if "data_sha256" in r else "—"}</td></tr>'
        for i, r in enumerate(done['requests']))
    v['free_rows'] = ''.join(
        f'<tr><th scope="row">{code(name)}</th><td>{", ".join(code(call["arguments"][1]) for call in c["free_calls"])}</td>'
        f'<td>{", ".join(f"{code(site)} → {status}" for site, status in c["native_status_sites"])}</td></tr>'
        for name, c in ends.items())
    models = (('재시도 7사례', replay['modeled_continuation']), ('마무리 4사례', final['modeled_finalization']))
    v['model_rows'] = ''.join(
        f'<tr><th scope="row">{stage}</th><td>{code(pc)}</td><td>{MODELS.get(text, esc(text))}</td></tr>'
        for stage, apis in models for pc, text in apis.items())
    seen, rows = set(), []
    for f in data['selected_functions'] + terminal['selected_functions']:
        if f['address'] in seen:
            continue
        seen.add(f['address'])
        named = f['name'] not in FUNCTIONS
        rows.append(
            f'<tr><th scope="row">{code(f["name"]) if named else FUNCTIONS[f["name"]]}</th>'
            f'<td><code>{f["address"]:#x}</code>~<code>{f["candidate_end"]:#x}</code></td><td class="n">{n(f["size"])}</td>'
            f'<td>{code(f["original_file_offset"])}</td><td>{"ELF 심볼 크기" if named else "분석자가 정한 경계"}</td>'
            f'<td>{code(f["sha256"][:16] + "…")}</td></tr>')
    v['function_rows'] = ''.join(rows)
    v['function_count'] = str(len(rows))
    v['word_rows'] = ''.join(
        f'<tr><th scope="row">{WORD_ROLES.get(e["role"], esc(e["role"]))}</th><td>{name}</td><td class="n">{len(e["words"])}</td></tr>'
        for name, doc in (('burn-continuation.json', data), ('burn-finalization.json', terminal)) for e in doc['evidence'])
    v['words'], v['words_final'] = str(words), str(words_final)
    v['block0_sha256'] = final['source_hashes']['primary_aggregate_sha256']
    v['spare_sha256'] = final['source_hashes']['primary_aggregate_spare_sha256']
    v['block10_sha256'] = rebuilt['main_sha256']
    v['extended_sha256'] = rebuilt['direct_sha256']
    v['final_sha256'] = done['requests'][3]['data_sha256']
    v['schedule_sha256'] = prefix['schedule']['sha256']
    v['engine'] = esc(replay['engine'])
    v['k3_commit'] = data['comparison']['commit']
    page = (ROOT/'analysis/continuation-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'burn-continuation-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built burn-continuation-report.html')


if __name__ == '__main__':
    build_burn()
