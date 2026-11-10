"""Render the storage preflight and lens readiness report (storage-readiness-report.html).

The prose and the diagrams live in analysis/lifecycle-template.html. This builder supplies the
tables and counts from analysis/loader-storage.json and analysis/lens-readiness.json, and checks
that the values quoted in the static prose and diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

PROGRAM_CASES = {
    'equal-one': '1섹터, 내용이 같음',
    'equal-two': '2섹터, 내용이 같음',
    'write-fail': '기록(연산 5)이 오류',
    'read-fail': '다시 읽기(연산 4)가 오류',
    'mismatch-first': '첫 바이트가 다름',
    'mismatch-middle': '512번째 바이트가 다름',
    'mismatch-last': '마지막 바이트가 다름',
    'mismatch-no-map': '블록 맵 없이, 512번째 바이트가 다름',
}
DISPATCH = {
    4: '데이터 읽기. 관측한 코드에서는 섹터당 512바이트',
    5: '데이터 기록. 섹터당 512바이트. 어떤 명령을 쓸지는 핸들 <code>+0x11dc</code>와 장치 플래그에 따라 달라짐',
    6: '예비 영역 읽기. 본 데이터는 다루지 않고, 결과를 예비 영역 포인터로 내보냄',
    8: '블록 지우기. 앞쪽 <code>0x80081b54</code>에서 핸들 <code>+0x11c4</code>로 블록 주소를 환산. 설정 바이트 <code>0xd0</code>, 명령 <code>0x107</code>',
}
STORAGE_MODELS = {
    'allocate zeroed synthetic heap': '메모리 할당: 0으로 채운 합성 메모리를 내줌',
    'cache maintenance no-op': '캐시 정리 요청: 아무 일도 하지 않음',
    'free no-op': '메모리 해제: 아무 일도 하지 않음',
    'diagnostic log no-op': '진단 로그: 아무 일도 하지 않음',
    'header diagnostic no-op': '헤더 진단 출력: 아무 일도 하지 않음',
    'card callback supplies original package bytes': '카드 읽기 함수: 원본 패키지의 바이트를 그대로 건넴',
    'existing-media header returns synthetic installed header': '설치된 헤더 읽기: 합성 설치 헤더를 돌려줌',
    'synthetic zone geometry': '저장장치 형상 조회: 합성 값을 돌려줌',
    'operation 6 fills 16 spare bytes with FF and returns 0; operation 8 returns 0':
        '저장장치 요청: 연산 6에는 예비 영역 16바이트를 FF로 채워 0을 반환, 연산 8에는 0을 반환',
    'operation 5 returns fixture status; operation 4 supplies synthetic readback and fixture status':
        '저장장치 요청: 연산 5에는 시험용 상태값을 반환, 연산 4에는 합성 데이터와 시험용 상태값을 반환',
}
STORAGE_FUNCTIONS = {
    'Spare-read request adapter': '예비 영역 읽기 요청 함수',
    'Block assessment': '블록 검사 함수',
    'Program/readback and comparison': '기록·비교 함수',
}
STORAGE_WORDS = {
    'Burn entry, map, block assessment, erase and program call sites': 'BurnNand 진입, 섹션 맵, 블록 검사, 지우기·기록 호출 자리',
    'Spare request and user-area guard': '예비 영역 요청과 사용자 영역 판정',
    'Program followed by readback and byte comparison': '기록 뒤의 다시 읽기와 바이트 비교',
    'FCU route and descriptor branches': '저장 계층의 경로와 연산별 분기',
}
LENS_CASES = {
    'success': '모든 응답이 성공',
    'regular-map-denied': 'regular 연산이 기능 표에서 거부됨',
    'regular-reply-fails': 'regular 응답이 실패',
    'primary-spec-fails': 'primary의 사양 응답이 실패',
    'search-map-denied': '검색 연산이 기능 표에 없음',
    'partial-map-fails': '기능 표를 받는 도중 실패',
    'already-powered': '이미 전원이 켜져 있음',
    'single-failed-reply': 'SingleRegular 응답 실패',
    'vd-sync-failed-reply': 'VD-sync 응답 실패 (새 바이트 없음)',
    'vd-sync-failed-prefix': 'VD-sync 응답 실패 (앞 5바이트만 새 값)',
    'primary-refresh-failed': 'Primary 갱신 실패',
    'control-reset': '전체 리셋을 직접 호출',
    'mount-switch-open': '마운트 스위치가 열림',
    'detect-with-latch': '감지 인터럽트, 래치가 1',
    'detect-without-latch': '감지 인터럽트, 래치가 0',
}
LENS_MODELS = {
    'low-level sequence/port setup': '저수준 순서·포트 설정',
    'semaphore/worker control': '세마포어·작업자 제어',
    'interrupt line disable': '인터럽트 선 끄기',
    'mount BtoL pin control': '마운트 BtoL 핀 제어',
    'serial configuration': '직렬 통신 설정',
    'link frequency setup, returns 0': '통신 속도 설정 (0을 반환)',
    'delay': '지연',
    'lens worker queue clear': '렌즈 작업자 큐 비우기',
    'mount MoVd pin control': '마운트 MoVd 핀 제어',
    'lens port configuration': '렌즈 포트 설정',
    'tube-closed notification recipient': '경통 닫힘 알림을 받는 쪽',
    'mount-switch power control': '마운트 스위치 전원 제어',
    'mount timer scheduling': '마운트 타이머 예약',
    'interrupt line enable': '인터럽트 선 켜기',
    'synthetic power-enable input': '전원 켜짐 입력 (합성 값)',
    'record power-enable request without GPIO': '전원 켜기 요청을 기록만 함 (GPIO 없음)',
    'synthetic power-on check succeeds': '전원 켜짐 확인 (성공으로 응답)',
    'synthetic mount-detect pin': '마운트 감지 핀 (합성 값)',
    'synthetic mount-switch pin': '마운트 스위치 핀 (합성 값)',
    'record retry queue message': '재시도 큐 메시지를 기록',
    'LLC command statuses and receive bytes': 'LLC 명령의 상태값과 수신 바이트를 공급',
    'serial response/status injection below original transport admission': '직렬 응답과 상태값을 공급 (원본 명령 허용 검사의 아래쪽)',
    'fixed body temperature 25': '본체 온도를 25로 고정',
    'BtoL input low': 'BtoL 입력: 낮음',
    'LtoB input low': 'LtoB 입력: 낮음',
    'synthetic ready-to-communicate result 1': '통신 준비 결과: 1',
    'timer setup no-op': '타이머 설정: 아무 일도 하지 않음',
    'timer start no-op': '타이머 시작: 아무 일도 하지 않음',
    'timer cleanup no-op': '타이머 정리: 아무 일도 하지 않음',
    'timer stop no-op': '타이머 멈춤: 아무 일도 하지 않음',
    'supply event mask 0x100 at the wait boundary': '대기 지점에서 이벤트 마스크 <code>0x100</code>을 공급',
    'record recovery reentry and its input state; stop nested initialization': '복구용 초기화 재진입과 그때의 상태를 기록하고, 겹친 초기화는 멈춤',
}
LENS_WORDS = {
    'OR-only state writer and native control/data reset': '상태 바이트를 OR로만 쓰는 함수와 제어·데이터 리셋',
    'Power transition and conditional 0x08 writes': '전원 전환과 0x08 비트를 켜는 조건',
    'Map replies and ready store': '기능 표 응답과 준비 플래그 저장',
    'Independent AF and admission gates and unconditional reply copy': '서로 독립인 AF 판정과 명령 허용, 조건 없는 응답 복사',
    'Primary invalidation, failed buffer zeroing, and position getter': 'Primary의 무효화, 실패 때의 버퍼 0 채움, 위치 getter',
    'Single/VD regular cache behavior': 'Single·VD regular의 캐시 동작',
    'Dismount, power-off and native timeout reset': '렌즈 분리, 전원 끄기, 타임아웃 리셋',
    'Lens-thread message table and targets': '렌즈 스레드의 메시지 표와 목적지',
}
GLOBALS = {
    'communications_state': '통신 상태 바이트',
    'map_ready': '표 준비 플래그 (map-ready)',
    'group_bitmap': '그룹 비트맵',
    'operation_bitmap': '연산 비트맵',
    'search_operation_2_4': '검색 연산(그룹 2, 연산 4)의 허용 칸',
    'spec_valid': '사양 데이터의 유효 상태',
    'standard_valid': '표준 데이터의 유효 상태',
    'vd_status': 'VD 데이터(VDRC)의 유효 상태',
    'vdr_cache': 'VD 데이터 캐시',
    'vdr_receive_buffers': 'VD 수신 버퍼 두 개',
    'dismount_latch': '분리 래치',
}


def n(value):
    return f'{value:,}'


def code(value):
    return f'<code>{esc(value)}</code>'


def lens_row(label, after, extra=''):
    valid = ' · '.join(str(x) for x in after['validity'])
    return (f'<tr><th scope="row">{label}</th><td><code>0x{after["communications_state"]:02x}</code></td>'
            f'<td class="n">{after["map_ready"]}</td><td>{valid}</td>'
            f'<td><code>{after["current"]:#010x}</code></td><td class="n">{after["position_getter_status"]}</td>'
            f'<td class="n">{after["af_enable"]}</td><td>{"전달" if after["search_forwarded"] else "거부"}</td>{extra}</tr>')


def main():
    loader, lens = read('loader-storage.json'), read('lens-readiness.json')
    pre, replay = loader['replay']['preflight'], lens['replay']
    schedule = pre['schedule']

    # Values that the template quotes as fixed text in prose and diagrams.
    assert (pre['synthetic_blocks'], pre['sectors_per_block'], pre['sector_bytes']) == (1024, 256, 512)
    assert (pre['installed_header']['user_start_block'], pre['installed_header']['user_block_count'], pre['installed_header']['header_mode']) == (640, 384, 1)
    assert (schedule['operation_6'], schedule['operation_8'], schedule['total_modeled_requests']) == (2691, 640, 3331)
    assert schedule['operation_8_block_range'] == [0, 639]
    assert 640 * 3 + 384 * 2 + 3 == 2691 and 640 * 4 == 2560 and 384 * 2 == 768 and 2560 + 768 + 3 == 3331
    assert pre['card_reads'] == [{'original_file_offset': '0x1000c0', 'byte_count': 131072}]
    assert pre['first_operation_5'] == {'return_address': '0x80011e10',
                                        'arguments': ['0x10000000', '0x5', '0x0', '0x100', '0x10010000', '0x70007a98', '0x10']}
    assert pre['pending_data']['changed_byte_count'] == 281
    programs, users = loader['replay']['program_cases'], loader['replay']['user_range_cases']
    assert list(PROGRAM_CASES) == [c['name'] for c in programs] and len(users) == 7
    assert [c['result'] for c in programs] == [1, 1, 0, 0, 0, 0, 0, 0]
    assert [o['operation'] for o in loader['storage_dispatch']['operations']] == [4, 5, 6, 8]
    assert [o['handler'] for o in loader['storage_dispatch']['operations']] == ['0x80081f2c', '0x80081d20', '0x80082054', '0x80081fd0']
    storage_words, lens_words = len(list(witnesses(loader))), len(list(witnesses(lens)))
    assert (storage_words, lens_words) == (83, 153)
    assert (len(loader['boot_selected_functions']), len(loader['boot_anonymous_ranges']), len(lens['selected_functions'])) == (8, 3, 33)
    starts = replay['startup_cases']
    assert [c['after']['communications_state'] for c in starts] == [0x2F, 0x0F, 0x07, 0x23, 0x2F, 0x00, 0x6F]
    assert [c['after']['af_enable'] for c in starts] == [1, 1, 0, 0, 0, 0, 1]
    assert [c['after']['search_forwarded'] for c in starts] == [True, True, True, True, False, True, True]
    assert [c['after']['validity'][2] for c in starts] == [1, 0, 0, 1, 1, 0, 1]
    assert starts[6]['early_return_2'] is True and starts[5]['retry_messages'] == [1]
    caches = {c['case']: c['after'] for c in replay['cache_cases']}
    resets = {c['case']: c for c in replay['reset_cases']}
    good = starts[0]['after']
    assert caches['single-failed-reply']['vd_buffers_zero'] and caches['single-failed-reply']['validity'] == [1, 1, 1]
    assert caches['single-failed-reply']['position_getter_status'] == 1 and caches['single-failed-reply']['current'] == 0
    assert caches['vd-sync-failed-reply']['current'] == good['current'] and caches['vd-sync-failed-reply']['tail'] == good['tail']
    assert caches['vd-sync-failed-prefix']['current'] != good['current'] and caches['vd-sync-failed-prefix']['tail'] == good['tail']
    assert caches['primary-refresh-failed']['validity'] == [0, 0, 0] and caches['primary-refresh-failed']['current'] == good['current']
    assert caches['primary-refresh-failed']['position_getter_status'] == 0
    assert [resets[k]['after']['communications_state'] for k in resets] == [0, 0, 0, 0x2F]
    assert [resets[k]['latch'] for k in resets] == [0, 1, 0, 0]
    timeouts = replay['timeout_cases']
    assert [(t['map_ready_before'], t['result'], len(t['recovery_reentry'])) for t in timeouts] == [(0, 5, 0), (1, 5, 1)]
    assert timeouts[1]['after']['communications_state'] == 0 and timeouts[0]['after']['communications_state'] == 0x6F
    cases = len(starts) + len(replay['cache_cases']) + len(replay['reset_cases']) + len(timeouts)
    assert cases == 17
    assert '1 startup, 2 short VD AF, 3 ordinary VD regular, 4 single regular, 15 end sequence, 16 power-off/delay/restart, 17 mount switch control' in lens['findings']['thread']
    assert 'ORs 4 on primary return 1 and ORs 8 if primary returned 1 and regular returned 1 or 7' in lens['findings']['startup']

    v = {}
    v['program_rows'] = ''.join(
        f'<tr><th scope="row">{PROGRAM_CASES[c["name"]]} {code(c["name"])}</th><td class="n">{c["sectors"]}</td>'
        f'<td>{" → ".join("연산 %d: 상태 %d" % (e["operation"], e["status"]) for e in c["events"])}</td>'
        f'<td class="n">{n(c["compared_bytes_per_operand"])}</td><td class="n">{c["result"]}</td><td>{code(c["map"])}</td></tr>'
        for c in programs)
    v['user_rows'] = ''.join(
        f'<tr><td class="n">{c["header_mode"]}</td><td class="n">{c["start"]}</td><td class="n">{c["count"]}</td>'
        f'<td class="n">{n(c["block"])}</td><td>{"사용자 영역 (1)" if c["result"] else "아님 (0)"}</td></tr>' for c in users)
    v['dispatch_rows'] = ''.join(
        f'<tr><th scope="row">{o["operation"]}</th><td>{code(o["jump_word_va"])}</td><td>{code(o["handler"])}</td><td>{DISPATCH[o["operation"]]}</td></tr>'
        for o in loader['storage_dispatch']['operations'])
    firsts = (('연산 6 (예비 영역 읽기)', pre['first_operation_6']), ('연산 8 (지우기)', pre['first_operation_8']),
              ('연산 5 (기록, 실행 전에 멈춤)', pre['first_operation_5']))
    v['first_rows'] = ''.join(
        f'<tr><th scope="row">{label}</th><td>{code(r["return_address"])}</td><td><code class="wrap">{", ".join(r["arguments"][1:])}</code></td></tr>'
        for label, r in firsts)
    v['storage_model_rows'] = ''.join(
        f'<tr><th scope="row">{stage}</th><td>{code(pc)}</td><td>{STORAGE_MODELS.get(text, esc(text))}</td></tr>'
        for stage, apis in (('사전 검사', loader['replay']['modeled_prefix']), ('기록·비교 8사례', loader['replay']['modeled_program']))
        for pc, text in apis.items())
    rows = []
    for f in loader['boot_selected_functions'] + loader['boot_anonymous_ranges']:
        named = f['name'] not in STORAGE_FUNCTIONS
        rows.append(
            f'<tr><th scope="row">{code(f["name"]) if named else STORAGE_FUNCTIONS[f["name"]]}</th>'
            f'<td><code>{f["address"]:#x}</code>~<code>{f["candidate_end"]:#x}</code></td><td class="n">{n(f["size"])}</td>'
            f'<td>{code(f["original_file_offset"])}</td><td>{"ELF 심볼 크기" if named else "분석자가 정한 경계"}</td>'
            f'<td>{code(f["sha256"][:16] + "…")}</td></tr>')
    v['storage_function_rows'] = ''.join(rows)
    v['storage_word_rows'] = ''.join(
        f'<tr><th scope="row">{STORAGE_WORDS.get(e["role"], esc(e["role"]))}</th><td class="n">{len(e["words"])}</td></tr>'
        for e in loader['evidence'])
    v['schedule_sha256'] = schedule['sha256']
    v['incoming_sha256'] = pre['pending_data']['incoming_sha256']
    v['program_sha256'] = pre['pending_data']['program_source_sha256']

    v['lens_rows'] = ''.join(
        lens_row(f'{LENS_CASES[c["case"]]} {code(c["case"])}', c['after'],
                 f'<td class="n">{c["after"]["search_operation"]}</td>') for c in starts)
    after_rows = [lens_row(f'{LENS_CASES[c["case"]]} {code(c["case"])}', c['after'], '<td>—</td>') for c in replay['cache_cases']]
    after_rows += [lens_row(f'{LENS_CASES[c["case"]]} {code(c["case"])}', c['after'], f'<td>래치 {c["latch"]}</td>')
                   for c in replay['reset_cases']]
    after_rows += [lens_row(f'타임아웃, 직전의 표 준비 플래그가 {t["map_ready_before"]}', t['after'],
                            f'<td>결과 {t["result"]}, 재진입 {len(t["recovery_reentry"])}회</td>') for t in timeouts]
    v['state_rows'] = ''.join(after_rows)
    v['global_rows'] = ''.join(
        f'<tr><th scope="row">{GLOBALS[key]}</th><td>{", ".join(code(x) for x in (value if isinstance(value, list) else [value]))}</td></tr>'
        for key, value in lens['globals'].items())
    v['lens_model_rows'] = ''.join(
        f'<tr><th scope="row">{stage}</th><td>{code(pc)}</td><td>{LENS_MODELS.get(text, esc(text))}</td></tr>'
        for stage, apis in (('초기화·캐시·리셋', replay['models']), ('타임아웃 (추가)', replay['timeout_models']))
        for pc, text in apis.items())
    v['lens_function_rows'] = ''.join(
        f'<tr><th scope="row">{code(f["name"])}</th><td><code>{f["address"]:#x}</code>~<code>{f["candidate_end"]:#x}</code></td>'
        f'<td class="n">{n(f["size"])}</td></tr>' for f in lens['selected_functions'])
    v['lens_word_rows'] = ''.join(
        f'<tr><th scope="row">{LENS_WORDS.get(e["role"], esc(e["role"]))}</th><td class="n">{len(e["words"])}</td></tr>'
        for e in lens['evidence'])
    v['storage_words'], v['lens_words'] = str(storage_words), str(lens_words)
    v['lens_functions'] = str(len(lens['selected_functions']))
    v['engine'] = esc(replay['engine'])
    v['k3_loader'] = loader['comparison']['k3_commit']
    v['k3_lens'] = lens['comparison']['commit']
    page = (ROOT/'analysis/lifecycle-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'storage-readiness-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built storage-readiness-report.html')


if __name__ == '__main__':
    main()
