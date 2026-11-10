"""Render the distinct MAIN updater bridge and its bounded return semantics.

The prose and the diagrams live in analysis/update-service-template.html. This builder supplies
the case tables and counts from analysis/update-service.json and checks that the values quoted
in the static diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc

STAGING_OPTIONS = {
    (): ('정상 (보드 버전 2)', '모든 모델이 성공을 돌려줌'),
    ('board',): ('정상 (보드 버전 3)', '보드 버전 모델이 3을 돌려줌'),
    ('size',): ('빈 파일', '크기 조회 모델이 0을 돌려줌'),
    ('ready',): ('준비값 0', '파라미터 <code>0x11e</code>를 되읽은 값이 0'),
    ('format',): ('포맷 오류', '포맷 모델이 7을 돌려줌'),
    ('mount',): ('마운트 오류', '마운트 모델이 7을 돌려줌'),
    ('alloc_failure',): ('메모리 할당 실패', '할당 모델이 실패를 돌려줌'),
    ('open_input',): ('입력 파일 열기 실패', '열기 모델이 0을 돌려줌'),
    ('read',): ('짧은 읽기', '96바이트를 요청했는데 95바이트만 읽힘'),
    ('open_output',): ('출력 파일 열기 실패', '<code>I:\\UPG_FILE.ELF</code> 열기 모델이 0을 돌려줌'),
    ('write_status',): ('쓰기 오류', '하위 FileX 쓰기 모델이 상태 7을 돌려줌'),
}
STAGING_EVENTS = {
    'size': '파일 크기 조회', 'board': '보드 버전 조회', 'set_long': '파라미터 쓰기(32비트)', 'get_param': '파라미터 읽기',
    'format': '저장 매체 포맷', 'set_param': '파라미터 쓰기', 'mount': '저장 매체 마운트', 'allocate': '메모리 할당',
    'open': '파일 열기', 'read': '파일 읽기', 'close': '파일 닫기', 'filex_write': 'FileX 쓰기', 'free': '메모리 해제', 'log': '진단 출력',
}
BRIDGE_OPTIONS = {
    'burn': 'Burn → 7', 'media_open': '매체 열기 → 7', 'file_open': '파일 열기 → 7', 'seek': '파일 위치 이동 → 7',
    'read': '헤더 앞 64바이트 읽기 → 7', 'read_extended': '헤더 뒤 128바이트 읽기 → 7', 'file_close': '파일 닫기 → 7',
}
BOUNDARIES = {
    'size': '파일 크기 조회', 'board': '보드 버전 조회', 'set_long': '파라미터 쓰기(32비트)', 'get_param': '파라미터 읽기',
    'format': '저장 매체 포맷', 'mount': '저장 매체 마운트', 'set_param': '파라미터 쓰기', 'allocate': '메모리 할당',
    'free': '메모리 해제', 'open': '파일 열기', 'read': '파일 읽기', 'close': '파일 닫기', 'filex_write': 'FileX 쓰기',
    'log': '진단 출력', 'calloc': '0으로 채운 메모리 할당', 'alloc': '메모리 할당', 'media_open': 'FileX 매체 열기',
    'first': '디렉터리 첫 항목', 'next': '디렉터리 다음 항목', 'file_open': 'FileX 파일 열기', 'seek': 'FileX 위치 이동',
    'file_close': 'FileX 파일 닫기', 'media_close': 'FileX 매체 닫기', 'led_init': 'LED 초기화', 'led_status': 'LED 상태 표시',
    'burn': 'MAIN <code>Burn</code> 전체', 'reboot': '재부팅', 'lock': '뮤텍스 잠금', 'unlock': '뮤텍스 해제', 'thread': '스레드 생성',
}
STAGES = {'staging': '파일 준비', 'bridge': '기록 코드 진입·반환'}


def staging_detail(event):
    kind = event['kind']
    if kind in ('size', 'open'):
        extra = f', 모드 {event["mode"]}' if 'mode' in event else f', 크기 {event["size"]}'
        return f'<code>{esc(event["path"])}</code>{extra}'
    if kind in ('set_long', 'set_param'):
        key, value = event['arguments']
        return f'<code>{key:#x}</code> ← {value:,}'
    if kind in ('get_param', 'format', 'mount'):
        return f'<code>{event["selector"]:#x}</code>, 받은 값 {event["out_value"]}'
    if kind in ('allocate',):
        return f'{event["size"]}바이트'
    if kind in ('read', 'filex_write'):
        return f'{event["count"]}바이트'
    return ''


def bridge_row(number, case):
    options = case['options']
    outer = options.get('outer', False)
    conditions = [BRIDGE_OPTIONS[key] for key in options if key in BRIDGE_OPTIONS]
    if outer and options.get('sync', 1) == 0:
        start = '래퍼·비동기'
        conditions.append(f'스레드 생성 → {options["thread"]}')
    else:
        start = '래퍼·동기' if outer else 'I43'
    seen = {o['pc']: o['return_value'] for o in case['observations']}
    download = seen.get('0x805e5bd4', '—')
    adapter = seen.get('0x807f1f88', '—') if outer else case['result']
    wrapper = case['result'] if outer else '—'
    flag = case['updating'] if outer else '—'
    kinds = [e['kind'] for e in case['events']]
    reboot = '호출' if 'reboot' in kinds else ('없음' if 'burn' in kinds else '—')
    return (f'<tr><th scope="row">{number}</th><td>{start}</td><td>{", ".join(conditions) or "모두 성공"}</td>'
            f'<td class="n">{download}</td><td class="n">{adapter}</td><td class="n">{wrapper}</td>'
            f'<td class="n">{flag}</td><td>{reboot}</td></tr>')


def main():
    data = read('update-service.json')
    replay = data['bounded_replay']
    staging, bridge = replay['staging_cases'], replay['bridge_cases']
    names = {f['name']: f['address'] for f in data['selected_functions']}

    # Numbers that the template's prose and diagrams quote as fixed text.
    assert (len(staging), len(bridge)) == (11, 12)
    assert replay['header_original_offset'] == '0x100000' and replay['header_bytes'] == 192
    assert replay['staging_input_bytes'] == 96
    assert [e['result'] for c in staging[:2] for e in c['events'] if e['kind'] == 'board'] == [2, 3]
    assert next(e for e in staging[0]['events'] if e['kind'] == 'set_long')['arguments'] == [0x11e, 65537]
    assert (names['DownloadCard'], names['BurnGetHandle'], names['Burn'], names['BurnNand']) == (0x805e10ac, 0x805e4fe4, 0x805e5374, 0x805dd7b8)
    prior = data['prior_E01']
    assert (prior['get_handle'], prior['selected_callback'], prior['callback_field'], prior['hash_flag_field']) == ('0x8001b134', '0x80012654', '0x1254', '0x1278')
    burn = next(e for e in bridge[0]['events'] if e['kind'] == 'burn')
    assert (burn['arguments'][1:], burn['callback'], burn['device'], burn['hash_flag'], burn['kind_id']) == (['0x20000', '0x805e8854'], '0x805dd7b8', '0x8006444c', 0, 3)
    returns = lambda case: (case['observations'][0]['return_value'], case['observations'][1]['return_value'], case['result'], case['updating'])
    assert returns(bridge[8]) == (1, 0, 1, 0) and returns(bridge[9]) == (0, 254, 1, 0)
    assert [(c['result'], c['updating']) for c in bridge[10:]] == [(0, 1), (1, 1)]
    assert sum(len(e['words']) for e in data['evidence']) == 98 and len(data['selected_functions']) == 12
    assert len(data['resource_ranges']) == 2

    v = {}
    v['staging_rows'] = ''.join(
        f'<tr><th scope="row">{STAGING_OPTIONS[tuple(c["options"])][0]}</th><td>{STAGING_OPTIONS[tuple(c["options"])][1]}</td>'
        f'<td class="n">{c["result"]}</td></tr>' for c in staging)
    v['staging_events'] = ''.join(
        f'<tr><td class="n">{i}</td><td>{STAGING_EVENTS[e["kind"]]}</td><td><code>{e["api"]}</code></td><td>{staging_detail(e)}</td>'
        f'<td class="n">{"<code>" + format(e["result"], "#x") + "</code>" if e["kind"] in ("allocate", "open") else e["result"]}</td></tr>'
        for i, e in enumerate(staging[0]['events'], 1))
    v['bridge_rows'] = ''.join(bridge_row(i, c) for i, c in enumerate(bridge, 1))
    v['boundaries'] = ''.join(
        f'<tr><th scope="row">{STAGES.get(stage, esc(stage))}</th><td><code>{pc}</code></td><td>{BOUNDARIES.get(label, esc(label))}</td><td><code>{esc(label)}</code></td></tr>'
        for stage, apis in data['modeled_boundaries'].items() for pc, label in apis.items())
    v['function_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(f["name"])}</code></th><td><code>{f["address"]:#x}</code></td><td class="n">{f["size"]:,}</td></tr>'
        for f in data['selected_functions'])
    v['header_sha256'] = replay['header_sha256']
    v['staging_sha256'] = replay['staging_input_sha256']
    v['k3_commit'] = data['comparison']['commit']
    page = (ROOT/'analysis/update-service-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'update-service-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built update-service-report.html')


if __name__ == '__main__':
    main()
