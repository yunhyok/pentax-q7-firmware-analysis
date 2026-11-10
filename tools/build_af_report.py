"""Render AF request, cached completion and sequence-stop boundaries."""
from build_deep_report import ROOT, read, esc

# Short Korean descriptions of the fixture names in analysis/af-completion.json.
CASE_LABELS = {
    'search-ack-then-motion': '검색 성공 뒤 이동값 1 → 2 → 0',
    'phase-four-conditional-advance': '캡처 단계 4로 시작한 검색',
    'search-map-denied-then-invalid-zero': '연산 맵이 검색을 거부, 유효성 0인 이동값 0이 계속됨',
    'search-link-error-then-failed-regular-zero': '하위 링크 실패 뒤 정기 통신 실패로 캐시가 0',
    'search-late-worker-at-timeout': '작업자가 101번째 대기에서 결과를 기록',
    'search-inhibited-immediate-notify': '구동 제한 1, 대기 플래그 0: 큐 없이 즉시 완료',
    'search-ready-clear-forwarded': 'map-ready 0·AF 지원 0인데 검색이 하위 API까지 전달',
    'stop-ack-while-cache-moving': '이동 중 정지 명령 성공',
    'stop-map-denied-clears-check': '정지가 연산 맵에서 거부돼도 확인 상태 0',
    'stop-timeout-clears-check': '정지 메시지가 전달되지 않아 시간 초과',
    'reset-zero-during-motion-check': '상태 2에서 렌즈 제어 리셋',
    'search-queue-rejected': '큐가 제출을 거부(0)',
}
WAIT_LABELS = {
    'invalid-zero': '유효하지 않은 0',
    'invalid-moving-then-zero': '유효하지 않은 이동값 뒤 0',
    'nonzero-through-bound': '0x80을 계속 유지',
}
ABORT_LABELS = {
    'notify-no-sequence': '시퀀스 비활성',
    'notify-active-awake': '활성, 깨어 있음',
    'notify-active-sleeping': '활성, 잠듦',
    'notify-deferred-bk-cancel': 'blBKControl 1: 취소 보류',
    'separate-exit-wait': '별도 종료 대기',
}
MODES = {0: '검색', 1: '정지'}
ENTRIES = {'notify': '명령 <code>0xe0002</code>', 'exit-wait': '<code>WaitAFComplete</code>'}


def name_cell(name, labels, show_name=False):
    tail = f'<br><span class="small muted">{esc(name)}</span>' if show_name else ''
    return f'<th scope="row">{esc(labels[name])}{tail}</th>'


def event_text(event):
    if event[0] == 'set':
        return f'깨움 0x{event[1]:x}'
    _, mask, mode, timeout, release, status = event
    assert (mode, timeout) == (1, 0xFFFFFFFF)
    return f'0x{mask:02x} 대기 ({release}, {status})'


def main():
    data = read('af-completion.json')
    replay = data['replay']
    v = {}
    v['command_count'] = str(len(replay['command_cases']))
    v['wait_count'] = str(len(replay['wait_cases']))
    v['abort_count'] = str(len(replay['abort_cases']))
    v['total_cases'] = str(sum(len(replay[k]) for k in ('command_cases', 'wait_cases', 'abort_cases')))
    v['boundary_count'] = str(len(replay['modeled_boundaries']))
    v['words'] = str(sum(len(e['words']) for e in data['evidence']))
    v['functions'] = str(len(data['selected_functions']))
    v['engine'] = esc(replay['engine'])

    rows = []
    for row in replay['command_cases']:
        drives = [s for s in row['steps'] if s['action'] == 'drive']
        final = row['steps'][-1]
        rows.append(
            f'<tr>{name_cell(row["name"], CASE_LABELS, True)}'
            f'<td>{" → ".join(MODES[s["mode"]] for s in drives)}</td>'
            f'<td>{" → ".join(str(s["setter_return"]) for s in drives)}</td>'
            f'<td>{" → ".join(str(s["waits"]) for s in drives)}</td>'
            f'<td class="n">{final["motion_check_state"]}</td><td class="n">{final["af_complete"]}</td>'
            f'<td class="n">{final["capture_phase"]}</td></tr>')
    v['case_rows'] = ''.join(rows)

    pair = lambda p: f'({p[0]}, {p[1]})'
    v['wait_rows'] = ''.join(
        f'<tr>{name_cell(c["name"], WAIT_LABELS)}<td>{pair(c["initial"])}</td>'
        f'<td>{", ".join(pair(s) for s in c["samples"]) or "없음"}</td><td class="n">{c["waits"]}</td>'
        f'<td>{"함수가 반환" if c["returned"] else "도구가 다음 대기 분기에서 중단 (<code>" + c["stop_pc"] + "</code>)"}</td></tr>'
        for c in replay['wait_cases'])

    v['abort_rows'] = ''.join(
        f'<tr>{name_cell(c["name"], ABORT_LABELS)}<td>{ENTRIES[c["entry"]]}</td>'
        f'<td>{c["sequence"]} / {c["sleeping"]}</td><td class="n">{c["bk_control"]}</td>'
        f'<td>{"<br>".join(event_text(e) for e in c["events"]) or "없음"}</td>'
        f'<td class="n">{c["stop_command"]}</td><td>{c["enable_caf"]} / {c["quit_caf"]}</td><td class="n">{c["bk_cancel"]}</td></tr>'
        for c in replay['abort_cases'])

    reg = data['queue_delivery_regression']
    v['reg_submission'] = str(reg['submission_status'])
    v['reg_poll'] = str(reg['scheduled_poll'])
    v['regression_rows'] = ''.join(
        f'<tr><th scope="row">{label}</th><td class="n">{r["waits"]}</td>'
        f'<td>{"없음" if r["worker_result"] is None else r["worker_result"]}</td><td class="n">{r["pending"]}</td>'
        f'<td class="n">{r["setter_result"]}</td><td class="n">{r["link_calls"]}</td></tr>'
        for label, r in (('정상 시험', reg['normal']),
                         ('시험용 변형' + (' (검사가 거부함)' if reg['mutant']['rejected'] else ''), reg['mutant'])))

    v['boundary_rows'] = ''.join(
        f'<tr><th scope="row"><code>{a}</code></th><td>{esc(t)}</td></tr>'
        for a, t in replay['modeled_boundaries'].items())
    v['evidence_rows'] = ''.join(
        f'<tr><th scope="row">{esc(e["role"])}</th><td class="n">{len(e["words"])}</td></tr>' for e in data['evidence'])
    v['function_rows'] = ''.join(
        f'<tr><th scope="row"><code class="wrap">{esc(f["name"])}</code></th><td><code>0x{f["address"]:08x}</code></td>'
        f'<td class="n">{f["size"]:,}</td><td><code>{f["sha256"][:16]}…</code></td></tr>'
        for f in data['selected_functions'])
    v['trace_limits'] = ' '.join(esc(t) for t in data['trace_limitations'])
    v['k3_commit'] = data['comparison']['commit']

    page = (ROOT/'analysis/af-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'af-completion-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built af-completion-report.html')


if __name__ == '__main__':
    main()
