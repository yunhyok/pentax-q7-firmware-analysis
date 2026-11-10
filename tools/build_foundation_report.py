"""Render the loader input/section-map and lens-policy report.

The prose and the diagrams live in analysis/foundation-template.html. This builder supplies the
case tables and counts from analysis/loader-foundation.json and analysis/lens-foundation.json and
checks that the values quoted in the static diagrams still match that evidence.
"""
from collections import Counter

from build_deep_report import ROOT, read, esc

CARD_CASES = {
    'double-read-equal': '두 번 읽은 내용이 같음',
    'mismatch-retry-success': '첫 시도는 내용이 다르고, 다시 읽어 같음',
    'mismatch-both-attempts': '두 시도 모두 내용이 다름',
    'different-actual-lengths': '두 번 읽힌 길이가 다름 (64와 63)',
    'equal-short-reads': '두 번 모두 8바이트만 읽힘',
    'equal-empty-success-reads': '두 번 모두 0바이트가 읽힘 (상태는 성공)',
    'first-read-error': '첫 읽기에서 오류',
    'second-read-error': '둘째 읽기에서 오류',
    'first-rewind-error': '첫 되감기에서 오류',
    'mismatch-rewind-error': '내용이 달라 되감다가 오류',
    'hash-worker-success': '해시 판정 성공',
    'hash-worker-retry-success': '첫 판정 실패, 다시 읽어 성공',
    'hash-worker-fails-twice': '두 번 모두 판정 실패',
    'hash-worker-rewind-error': '판정 실패 뒤 되감다가 오류',
}
MAP_CASES = {
    'compatible-existing-map': '설치 헤더가 업데이트와 맞음',
    'resource-B-size-mismatch': '설치 헤더의 Resource B 가상 섹터 수를 1 늘림',
    'protected-code-and-A-span-mismatch': '설치 헤더의 섹션 2 길이를 바꿈',
    'unprotected-code-and-A-span-mismatch': '설치 헤더의 섹션 2 길이를 바꿈',
    'protected-section3-start-mismatch': '설치 헤더의 섹션 3 시작 위치를 바꿈',
    'unsupported-user-area-mode': '업데이트 헤더의 사용자 영역 모드를 1로 바꿈',
    'insufficient-sectors': '저장장치의 총 섹터 수를 절반으로 줄임',
    'unknown-media-size': '저장장치 크기를 알 수 없는 값(<code>0xffffffff</code>)으로 둠',
}
LOADER_MODELS = {
    'alloc': '메모리 할당', 'cache': '캐시 처리', 'free': '메모리 해제', 'log': '진단 출력', 'read': '파일 읽기',
    'seek': '파일 되감기', 'hash_init': '해시 시작', 'hash_update': '해시 데이터 추가', 'hash_finalize': '해시 판정',
    'header diagnostic output': '헤더 진단 출력', 'payload': '카드 페이로드 읽기', 'media_header': '설치된 헤더 읽기',
    'zones': '저장장치 크기 조회',
}
LENS_STAGES = {'capability': '기능 표·AF 판정', 'data': '캐시 값 읽기', 'speed': '속도 변환', 'acknowledgement': '요청 응답', 'completion': '이동 완료'}


def n(value):
    return f'{value:,}'


def flag(value):
    return '예' if value else '아니오'


def tuples(requests):
    return ' → '.join('(' + ', '.join(str(x) for x in r) + ')' for r in requests)


def main():
    loader = read('loader-foundation.json')
    lens = read('lens-foundation.json')
    replay = loader['replay']
    lens_replay = lens['replay']
    accounting = loader['payload_accounting']
    prefix = replay['burn_nand_prefix']
    compatible = replay['section_map_cases'][0]

    # Numbers that the template's prose and diagrams quote as fixed text.
    counts = [len(replay[key]) for key in ('card_cases', 'protection_cases', 'section_pointer_cases', 'section_map_cases')]
    assert counts == [14, 84, 8, 8] and sum(counts) == 114
    assert replay['callback'] == {'table': '0x800a74dc', 'read': '0x80019014', 'ready': '0x80019390', 'ready_return': 1}
    assert (prefix['entry'], prefix['stop'], prefix['map_return']) == ('0x80012654', '0x80012ff0', 0)
    assert compatible['name'] == 'compatible-existing-map' and compatible['total_sectors'] == 262144
    assert [(s['section'], s['start_sector'], s['span_sectors'], s['file_sectors'], s['protected']) for s in compatible['output_sections']] == [
        (0, 0, 0, 0, 0), (1, 0, 2560, 2437, 0), (2, 2560, 79360, 31832, 0), (3, 81920, 24576, 0, 1),
        (4, 106496, 4096, 0, 1), (5, 110592, 53248, 0, 1), (6, 163840, 98304, 0, 1)]
    assert (accounting['code_chunk_count'], accounting['resource_a_chunk_count'], accounting['total_chunks']) == (10, 125, 135)
    assert (accounting['payload_start'], accounting['payload_size'], accounting['resource_a_start'], accounting['first_resource_elf_start']) == (
        '0x1000c0', 135 * 0x20000, '0x2400c0', '0x2402c0')
    assert (loader['validation']['word_count'], loader['validation']['file_word_count']) == (117, 20)
    assert (loader['validation']['boot_function_count'], loader['validation']['anonymous_extent_count']) == (17, 2)
    lens_counts = [len(lens_replay[key]) for key in ('capability_cases', 'data_cases', 'speed_cases', 'acknowledgement_cases', 'completion_cases')]
    assert lens_counts == [6, 3, 7, 7, 9] and sum(lens_counts) == lens['validation']['replay_fixture_count'] == 32
    assert (lens['validation']['function_count'], lens['validation']['original_word_witness_count']) == (67, 214)

    v = {}
    v['card_rows'] = ''.join(
        f'<tr><th scope="row">{CARD_CASES.get(c["name"], esc(c["name"]))}</th><td class="n">{c["hash_flag"]}</td>'
        f'<td class="n">{sum(e["kind"] == "read" for e in c["events"])}</td>'
        f'<td class="n">{sum(e["kind"] == "relative_seek" for e in c["events"])}</td><td class="n">{c["result"]}</td></tr>'
        for c in replay['card_cases'])
    summary = Counter((c['section'], c['result']) for c in replay['protection_cases'])
    v['protection_rows'] = ''.join(
        f'<tr><th scope="row">{section}</th><td class="n">{summary[(section, 1)]}</td><td class="n">{summary[(section, 0)]}</td></tr>'
        for section in sorted({c['section'] for c in replay['protection_cases']}))
    v['pointer_rows'] = ''.join(
        f'<tr><th scope="row">{c["section"]}</th><td><code>+{c["header_offset"]}</code></td></tr>' for c in replay['section_pointer_cases'])
    v['map_rows'] = ''.join(
        f'<tr><th scope="row">{MAP_CASES.get(c["name"], esc(c["name"]))}</th><td class="n">{n(c["total_sectors"]) if c["total_sectors"] < 0xffffffff else "알 수 없음"}</td>'
        f'<td class="n">{c["handle_protect"]}</td><td class="n">{c["result"]}</td><td><code>{esc(c["name"])}</code></td></tr>'
        for c in replay['section_map_cases'])
    v['section_rows'] = ''.join(
        f'<tr><th scope="row">{s["section"]}</th><td class="n">{n(s["start_sector"])}</td><td class="n">{n(s["span_sectors"])}</td>'
        f'<td class="n">{n(s["file_sectors"])}</td><td>{flag(s["protected"])}</td></tr>' for s in compatible['output_sections'])
    v['header_rows'] = ''.join(
        f'<tr><th scope="row">{esc(f["name"])}</th><td><code>{f["header_offset"]}</code></td>'
        f'<td><code>0x{f["value"]:x}</code></td><td class="n">{n(f["value"]) if f["value"] < 0x80000000 else "—"}</td></tr>'
        for f in loader['header']['fields'] if int(f['header_offset'], 16) <= 0x234)
    models = dict(replay['modeled_functions'], **prefix['additional_modeled_functions'])
    v['loader_models'] = ''.join(
        f'<tr><td><code>{pc}</code></td><td>{LOADER_MODELS.get(role, esc(role))}</td></tr>' for pc, role in models.items())
    v['capability_rows'] = ''.join(
        f'<tr><td><code>{c["communications_state"]:#04x}</code></td><td>{", ".join(str(g) for g in c["supported_groups"]) or "없음"}</td>'
        f'<td class="n">{c["group2_operation4"]}</td><td class="n">{c["expected_af"]}</td><td class="n">{c["expected_native_search_result"]}</td>'
        f'<td>{tuples(c["observed_map_requests"])}</td></tr>' for c in lens_replay['capability_cases'])
    v['speed_rows'] = ''.join(
        f'<tr><td class="n">{c["status"]}</td><td class="n">{n(c["raw_u16"])}</td><td class="n">{n(c["expected_steps"])}</td></tr>'
        for c in lens_replay['speed_cases'])
    v['ack_rows'] = ''.join(
        f'<tr><td class="n">{c["inhibit_byte"]}</td><td class="n">{"응답 없음" if c["acknowledge_after_waits"] is None else c["acknowledge_after_waits"]}</td>'
        f'<td class="n">{c["waits"]}</td><td>{"메시지 7" if c["messages"] else "보내지 않음"}</td><td class="n">{c["result"]}</td></tr>'
        for c in lens_replay['acknowledgement_cases'])
    v['completion_rows'] = ''.join(
        f'<tr><td class="n">{c["initial_state"]}</td><td class="n">{c["initial_count"]}</td><td class="n">{c["disable_start_wait"]}</td>'
        f'<td>{" → ".join(str(s["motion"]) for s in c["steps"])}</td><td>{" → ".join(str(s["state"]) for s in c["steps"])}</td>'
        f'<td class="n">{c["steps"][-1]["af_complete"]}</td></tr>' for c in lens_replay['completion_cases'])
    v['lens_models'] = ''.join(
        f'<tr><th scope="row">{LENS_STAGES.get(stage, esc(stage))}</th><td>{"<br>".join(esc(x) for x in apis) or "없음 (원본 코드만 실행)"}</td></tr>'
        for stage, apis in lens_replay['modeled_boundaries'].items())
    v['header_sha256'] = loader['header']['sha256']
    v['boot_sha256'] = loader['boot_elf_sha256']
    v['k3_commit'] = loader['comparison']['k3_commit']
    page = (ROOT/'analysis/foundation-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'loader-lens-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built loader-lens-report.html')


if __name__ == '__main__':
    main()
