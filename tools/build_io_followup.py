"""Render the first-block buffer and MD5 path report (loader-hash-report.html).

The prose and the diagrams live in analysis/loader-hash-template.html. This builder supplies the
tables and counts from analysis/header-hash.json and analysis/hash-card.json, and checks that the
values quoted in the static prose and diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

MODELS = {
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
    'capture three-word queue message and return fixture status': '큐 보내기: 세 워드 메시지를 받아 두고 시험용 상태값을 반환',
    'supply next three-word queue message and return fixture status': '큐 받기: 다음 세 워드 메시지를 건네고 시험용 상태값을 반환',
    "Deliver the fixture's full 80-byte data/digest record or read status 1 with actual count zero.":
        '파일 읽기: 80바이트 레코드(데이터 64 + 다이제스트 16) 전체를 건네거나, 상태 1과 읽은 길이 0을 반환',
    'Record original file, distance, high word and mode and return fixture status. No FileX media I/O.':
        '파일 되감기: 파일·거리·상위 워드·모드 인수를 기록하고 시험용 상태값을 반환. FileX 입출력은 없음',
    "Supply synthetic comparison RAM for the callback's allocation, including in flag-1 mode.":
        '메모리 할당: 비교용 합성 메모리를 내줌 (해시 플래그 1에서도 호출됨)',
    'Observe comparison RAM invalidation request without modifying cache.': '캐시 무효화 요청: 기록만 함',
    'Record the release of the synthetic comparison RAM.': '메모리 해제: 기록만 함',
    'Capture original three-word records; do not run RTOS queue send.':
        '큐 보내기: 원본 코드가 만든 세 워드 메시지를 받아 둠. RTOS의 큐는 실행하지 않음',
    "Deliver captured records, controlled worker stop, or the worker's native reply. No RTOS scheduling.":
        '큐 받기: 받아 둔 메시지, 작업자 종료용 메시지, 작업자가 실제로 낸 응답을 건넴. RTOS 스케줄링은 없음',
    'Accept diagnostic output without I/O.': '진단 출력: 받기만 함',
}
STAGES = {'header': '헤더 추적', 'mbr': '파티션 7사례', 'hash': '해시 작업자·래퍼', 'card': '카드 읽기 7사례'}
# What each observed store instruction writes, keyed by the first and last instruction address of a run.
WRITE_ROLES = (
    (0x80012FCC, 0x80012FD0, '저장장치 영역 정보 두 값 (<code>+0x3a8</code>, <code>+0x3ac</code>)', True),
    (0x80013E88, 0x80013EA4, '맨 앞 1,536바이트를 통째로 다시 복사 (값은 그대로)', False),
    (0x8001A3EC, 0x8001A3EC, '파티션 항목 0의 <code>+0</code> 바이트', True),
    (0x8001A410, 0x8001A414, '파티션 항목의 <code>+8</code> 시작값 (항목 4개)', True),
    (0x8001A420, 0x8001A424, '파티션 항목의 <code>+12</code> 길이 (항목 4개)', True),
    (0x8001A428, 0x8001A428, '파티션 항목의 <code>+4</code> 바이트 (항목 4개)', True),
    (0x8001A95C, 0x8001A95C, '크기 값 <code>+0x214</code>', True),
    (0x8001AC48, 0x8001AC68, '섹션 0 정보 36바이트를 <code>+0x3b0</code>에 복사', True),
    (0x8001AC8C, 0x8001ACB4, '섹션 1~6 정보 216바이트를 <code>+0x238</code>에 복사', True),
    (0x8001AF50, 0x8001AF54, '설치된 헤더의 두 값을 <code>+0x310</code>, <code>+0x314</code>에 복사', True),
    (0x8001AF58, 0x8001AF58, '<code>+0x230</code>에 복사 (이 입력에서는 같은 값)', False),
    (0x8001AF78, 0x8001AF84, '설치된 헤더 <code>0x318</code>~<code>0x398</code>의 128바이트 복사 (이 입력에서는 같은 값)', False),
)
CARD_CASES = {
    'match': '다이제스트가 일치',
    'first-digest-byte-retry-match': '다이제스트 첫 바이트가 달랐고, 다시 읽어 일치',
    'last-digest-byte-retry-new-payload': '다이제스트 끝 바이트가 달랐고, 다시 읽은 새 데이터로 일치',
    'first-and-last-digest-byte-fail': '두 번 모두 불일치 (첫 바이트, 끝 바이트)',
    'digest-mismatch-seek-error': '불일치 뒤 되감기에서 오류',
    'file-read-error': '첫 읽기에서 오류',
    'digest-mismatch-retry-read-error': '불일치 뒤 다시 읽기에서 오류',
}
WORKER_CASES = {
    'empty': '빈 입력',
    'abc': '“abc” 3바이트',
    'split': '129바이트를 나눠 넣음',
    'mismatch-first': '기대값의 첫 바이트가 다름',
    'mismatch-last': '기대값의 끝 바이트가 다름 (나눠 넣음)',
    'clear-bit29': '주소의 <code>0x20000000</code> 비트가 켜진 입력',
    'set-bit31': '주소의 <code>0x40000000</code> 비트가 켜진 입력',
    'unknown-command': '모르는 명령 <code>0x99</code>가 끼어 있음',
}
WRAPPERS = {'0x8001ba40': 'BurnHashInit', '0x8001ba74': 'BurnHashUpdate', '0x8001baac': 'BurnHashFanalize'}
EXTENTS = {'ELF32 STT_FUNC st_size': 'ELF 심볼 크기'}
FUNCTIONS = {'MD5 compression helper': 'MD5 압축 함수 (이름 없음)', 'sCardFunc.read callback (unnamed)': '카드 읽기 함수 (이름 없음)'}
WORD_ROLES = {
    'Native program-buffer writes, one witness per observed instruction': '기록 버퍼에 쓴 명령 (관측한 명령마다 하나)',
    'Section map size arithmetic and header destinations': '섹션 맵의 크기 계산과 헤더 안 목적지',
    'Partition gate and field mapping': '파티션 쓰기의 조건과 필드 대응',
    'Hash queues, dispatcher and native digest calls': '해시 큐, 명령 분기, MD5 호출',
    'Hash wrapper message words and ignored queue status': '해시 래퍼의 메시지와 무시되는 큐 상태값',
    'MD5 primitive entries and count/padding path': 'MD5 함수의 진입점과 길이·패딩 처리',
    'Original callback table, flag check, and FileX full-read branch': '카드 함수 표, 플래그 검사, 전체 읽기 분기',
    'Original callback hashes actual length minus trailer, then retries or frees': '읽은 길이에서 16을 뺀 만큼 해시, 그 뒤 재시도·해제',
    'Native queue wrappers stage codes 0, 1, 2 and accept reply 3': '래퍼가 보내는 명령 0·1·2와 응답 3의 처리',
    'Native worker dispatch, MD5 append/finish and equality/mismatch replies': '작업자의 분기, MD5 추가·마무리, 일치·불일치 응답',
}


def n(value):
    return f'{value:,}'


def code(value):
    return f'<code>{esc(value)}</code>'


def build_loader():
    data, card = read('header-hash.json'), read('hash-card.json')
    trace = data['header_replay']['trace']
    replay, cards = data['hash_replay'], card['replay']['cases']
    functions = data['boot_selected_functions']

    # Values that the template quotes as fixed text in prose and diagrams.
    ranges = trace['changed_ranges_end_exclusive']
    size = lambda lo, hi: sum(b - a for a, b in ranges if lo <= a and b <= hi)
    assert trace['source']['changed_byte_count'] == sum(b - a for a, b in ranges) == 281
    assert (size(0x214, 0x215), size(0x238, 0x318), size(0x3A8, 0x3D4), size(0x5BE, 0x5FE)) == (1, 224, 44, 12)
    assert max(b for _, b in ranges) <= 1536 and trace['mbr_offset'] == 0x400
    assert (trace['event_count'], trace['before_copy_events'], trace['final_copy_events']) == (3242, 170, 3072)
    assert trace['final_copy_byte_preserving'] is True
    assert trace['fields'] == {'0x214': 0x13600, '0x310': 640, '0x314': 384, '0x3a8': 1, '0x3ac': 0}
    assert 0x1367B + 0x982 - 0xA00 + 3 == 0x13600 == 79360
    request = trace['first_program_request']
    assert request['arguments'][1:4] == ['0x5', '0x0', '0x100'] and request['arguments'][6] == '0x10'
    assert [p['raw_byte0'] for p in trace['partition_fields']] == [0x80] * 4
    assert [p['raw_byte4'] for p in trace['partition_fields']] == [1] * 4
    lengths = sorted({c['length'] for c in replay['primitive_cases']})
    assert lengths == [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129]
    assert (len(replay['primitive_cases']), len(replay['worker_cases']), len(replay['wrapper_cases'])) == (26, 8, 9)
    assert len(data['header_replay']['mbr_cases']) == 7 and len(cards) == 7
    assert sum(len(c['workers']) for c in cards) == 9
    assert (card['callback']['synthetic_input_bytes'], card['callback']['synthetic_trailing_digest_bytes']) == (64, 16)
    assert (card['callback']['entry'], card['callback']['pointer_table'], card['callback']['hash_flag_offset']) == ('0x80019014', '0x800a74dc', '0x1278')
    assert all(c['hash_flag'] == 1 for c in cards)
    assert all(e[1:] == [268460032, 80, 0, 3, e[5]] for c in cards for e in c['callback_events'] if e[0] == 'seek')
    words_header, words_card = len(list(witnesses(data))), len(list(witnesses(card)))
    assert (words_header, words_card) == (101, 71)
    assert (len(functions), len(data['boot_anonymous_ranges']), len(card['selected_functions'])) == (13, 1, 10)

    def owner(address):
        return next((f['name'] for f in functions if f['address'] <= address < f['candidate_end']), '')

    def role(address):
        return next((text, changes) for lo, hi, text, changes in WRITE_ROLES if lo <= address <= hi)

    v = {}
    v['range_rows'] = ''.join(
        f'<tr><td><code>{lo:#05x}</code>{"" if hi - lo == 1 else f"~<code>{hi - 1:#05x}</code>"}</td><td class="n">{hi - lo}</td>'
        f'<td>{"MBR 파티션 표" if lo >= 0x400 else "헤더"}</td></tr>' for lo, hi in ranges)
    groups = []
    for g in trace['groups']:
        address = int(g['pc'], 16)
        text, changes = role(address)
        groups.append(
            f'<tr><td>{code(g["pc"])}</td><td>{code(owner(address))}</td><td class="n">{n(g["events"])}</td>'
            f'<td><code>{g["min_offset"]:#05x}</code>~<code>{g["end_exclusive"] - 1:#05x}</code></td>'
            f'<td>{text}</td><td>{"바뀜" if changes else "그대로"}</td></tr>')
    v['group_rows'] = ''.join(groups)
    v['group_count'] = str(len(trace['groups']))
    v['partition_rows'] = ''.join(
        f'<tr><th scope="row">{r["id"]}</th><td><code>0x{r["raw_byte0"]:02x}</code></td><td class="n">{r["raw_byte4"]}</td>'
        f'<td class="n">{n(r["raw_u32_at8"])}</td><td class="n">{n(r["raw_u32_at12"])}</td></tr>'
        for r in trace['partition_fields'])
    v['mbr_case_rows'] = ''.join(
        f'<tr><td class="n">{r["partition_id"]}</td><td class="n">{r["span"]}</td><td>{"씀" if r["writes"] else "쓰지 않음"}</td>'
        f'<td><code>0x{r["boot_byte"]:02x}</code>{" (원래 값)" if r["boot_byte"] == 0xA5 else ""}</td>'
        f'<td>{code(hex(r["start"])) if r["writes"] else "—"}</td><td>{code(hex(r["length"])) if r["writes"] else "—"}</td></tr>'
        for r in data['header_replay']['mbr_cases'])
    v['primitive_rows'] = ''.join(
        f'<tr><td class="n">{c["length"]}</td><td>{" + ".join(str(x) for x in c["chunks"])}</td><td>{code(c["digest"])}</td></tr>'
        for c in replay['primitive_cases'])
    digest = {c['length']: c['digest'] for c in replay['primitive_cases']}
    v['md5_empty'], v['md5_abc'] = digest[0], digest[3]
    v['worker_rows'] = ''.join(
        f'<tr><th scope="row">{WORKER_CASES[c["name"]]} {code(c["name"])}</th><td class="n">{c["length"]}</td>'
        f'<td>{" → ".join(str(r[0]) if r[0] < 10 else hex(r[0]) for r in c["requests"])}</td>'
        f'<td>{code(c["normalized_pointer"])}</td><td class="n">{c["replies"][0][0]}</td></tr>'
        for c in replay['worker_cases'])
    dash = lambda value: '—' if value is None else str(value)
    v['wrapper_rows'] = ''.join(
        f'<tr><th scope="row">{code(WRAPPERS[c["function"]])} {code(c["name"])}</th><td class="n">{dash(c["send_status"])}</td>'
        f'<td class="n">{dash(c["receive_status"])}</td><td class="n">{dash(c["reply"])}</td><td class="n">{c["result"]}</td></tr>'
        for c in replay['wrapper_cases'])
    v['card_rows'] = ''.join(
        f'<tr><th scope="row">{CARD_CASES[c["name"]]} {code(c["name"])}</th>'
        f'<td class="n">{sum(e[0] == "read" for e in c["callback_events"])}</td>'
        f'<td class="n">{sum(e[0] == "seek" for e in c["callback_events"])}</td>'
        f'<td class="n">{len(c["workers"])}</td>'
        f'<td>{" → ".join(str(w["delivered_reply"][0]) for w in c["workers"]) or "—"}</td><td class="n">{c["result"]}</td></tr>'
        for c in cards)
    seen, rows = set(), []
    for f in functions + data['boot_anonymous_ranges'] + card['selected_functions']:
        if f['address'] in seen:
            continue
        seen.add(f['address'])
        basis = EXTENTS.get(f['extent_basis'], '분석자가 정한 경계')
        rows.append(
            f'<tr><th scope="row">{FUNCTIONS.get(f["name"]) or code(f["name"])}</th><td><code>{f["address"]:#x}</code>~<code>{f["candidate_end"]:#x}</code></td>'
            f'<td class="n">{n(f["size"])}</td><td>{code(f["original_file_offset"])}</td><td>{basis}</td>'
            f'<td>{code(f["sha256"][:16] + "…")}</td></tr>')
    v['function_rows'] = ''.join(rows)
    v['function_count'] = str(len(rows))
    v['word_rows'] = ''.join(
        f'<tr><th scope="row">{WORD_ROLES.get(e["role"], esc(e["role"]))}</th><td>{name}</td><td class="n">{len(e["words"])}</td></tr>'
        for name, doc in (('header-hash.json', data), ('hash-card.json', card)) for e in doc['evidence'])
    models = (('header', data['header_replay']['modeled_prefix']), ('mbr', data['header_replay']['modeled_mbr']),
              ('hash', replay['modeled_worker_wrappers']), ('card', card['replay']['modeled_boundaries']))
    v['model_rows'] = ''.join(
        f'<tr><th scope="row">{STAGES[stage]}</th><td>{code(pc)}</td><td>{MODELS.get(text, esc(text))}</td></tr>'
        for stage, apis in models for pc, text in apis.items())
    v['incoming_sha256'] = trace['source']['incoming_sha256']
    v['program_sha256'] = trace['source']['program_source_sha256']
    v['request_return'] = request['return_address']
    v['request_arguments'] = ', '.join(request['arguments'])
    v['words_header'], v['words_card'] = str(words_header), str(words_card)
    v['engine'] = esc(data['header_replay']['engine'])
    v['k3_commit'] = data['comparison']['k3_commit']
    v['k3_numeric_commit'] = data['comparison']['numeric_reference']['commit']
    page = (ROOT/'analysis/loader-hash-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'loader-hash-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built loader-hash-report.html')


if __name__ == '__main__':
    build_loader()
