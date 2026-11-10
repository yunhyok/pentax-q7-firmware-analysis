"""Render two separately initialized MAIN updater prefix experiments.

The prose and the diagrams live in analysis/main-burn-template.html. This builder supplies the
tables and counts from analysis/main-burn-prefix.json and checks that the values quoted in the
static diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc

MODES = {'native_open': '시험 1', 'installed_header': '시험 2'}
MODELS = {
    'Supply zeroed synthetic allocation for the handle, media-info state and FileX buffer.':
        '핸들, 매체 정보 상태, FileX 버퍼용으로 0으로 채운 합성 메모리를 내줌',
    'Accept mutex get for the seeded synthetic mutex.': '미리 넣어 둔 합성 뮤텍스의 잠금 요청을 받아들임',
    'Accept mutex put for the seeded synthetic mutex.': '미리 넣어 둔 합성 뮤텍스의 해제 요청을 받아들임',
    'Record diagnostics without printing firmware text.': '진단 출력을 기록만 하고 펌웨어 문자열은 찍지 않음',
    'Supply synthetic primary, secondary, installed-header and card comparison buffers.':
        '기본·보조·설치 헤더·카드 비교용 합성 버퍼를 내줌',
    'Set synthetic medium selector and return 0xf1 at installed-media FileX open.':
        '설치 매체의 FileX 열기에서 합성 매체 선택 값을 넣고 <code>0xf1</code>을 반환',
    'Supply installed-media geometry of 256 sectors per block and 262144 sectors.':
        '설치 매체의 크기로 블록당 256섹터, 총 262,144섹터를 내줌',
    'After observing the first request, return op 6 with 16 FF spare bytes and op 4 with the 0x600-byte installed-header fixture.':
        '첫 요청을 관측한 뒤, 연산 6에는 FF 예비 바이트 16개를, 연산 4에는 <code>0x600</code>바이트 설치 헤더 시험값을 돌려줌',
    'Record card comparison-buffer cache invalidation without cache effects.': '카드 비교 버퍼의 캐시 무효화 요청을 기록만 함',
}
WORD_ROLES = {
    'Original DownloadCard call, MAIN BurnGetHandle, and callback table': 'DownloadCard의 호출, MAIN BurnGetHandle, 카드 함수 표',
    'MAIN Burn initialization, FileX geometry, buffer setup, HostAck and NAND callback': 'MAIN Burn의 초기화, 저장장치 크기 조회, 버퍼 준비, HostAck와 NAND 기록 함수 호출',
    'Installed FileX open to first NAND ID request': '설치 매체의 FileX 열기에서 첫 NAND ID 요청까지',
    'MAIN NAND installed header, card reader, and later map/storage bindings': 'MAIN BurnNand의 설치 헤더 요청, 카드 읽기, 그 뒤의 맵·저장 호출',
    'E01 homologous BurnNand call and handle words': 'E01 BurnNand에서 대응하는 호출과 핸들 접근',
}


def n(value):
    return f'{value:,}'


def main():
    data = read('main-burn-prefix.json')
    replay = data['bounded_replay']
    source = data['source']
    first, second = replay['native_open'], replay['installed_header']
    contract = data['call_contract']
    compare = source['comparison']
    functions = {f['names'][0]: f for f in source['main_functions']}
    e01 = source['boot_functions'][0]

    # Numbers that the template's prose and diagrams quote as fixed text.
    assert (contract['main']['burn'], contract['main']['burn_nand'], contract['main']['get_handle']) == ('0x805e5374', '0x805dd7b8', '0x805e4fe4')
    assert contract['main']['card_table'] == {'address': '0x805e8854', 'read': '0x805e1684', 'host_ack': '0x805e1a00'}
    assert (first['stop_before'], first['vex_blocks'], first['arguments'][2]) == ('0x80053124', 281, '0x2')
    assert second['first_nand_ex']['vex_blocks'] == 134 and second['first_card_filex']['vex_blocks'] == 156
    assert second['first_nand_ex']['arguments'][2:5] == ['0x6', '0x0', '0x1']
    assert second['first_card_filex']['arguments'][2] == '0x20000'
    requests = [(e['operation'], e['sector'], e['count']) for e in second['events'] if 'operation' in e]
    assert requests == [(6, 0, 1), (4, 0, 3)]
    geometry = next(e['geometry'] for e in second['events'] if 'geometry' in e)
    assert geometry == [256, 262144]
    assert next(e['result'] for e in second['events'] if e['api'] == '0x80067700') == 0xf1
    assert (replay['fixture']['update_header']['size'], replay['fixture']['installed_header']['size']) == (192, 0x600)
    assert replay['fixture']['installed_header']['borrowed_package_offset'] == '0x1000c0'
    assert (compare['words'], compare['byte_identical_words'], compare['same_primary_opcode']) == (2760, 2166, 2760)
    assert functions['BurnNand']['size'] == e01['size'] == 11040 and e01['address'] == '0x80012654'
    assert sum(len(g['words']) for g in source['main_words']) == 98 and len(source['main_functions']) == 24
    assert sum(len(g['words']) for g in source['e01_words']) == 11
    assert functions['HostAck']['size'] == 8
    ready = read('loader-foundation.json')['anonymous_functions'][1]
    assert ready['label'] == 'card_ready' and ready['sha256'] == functions['HostAck']['sha256']

    v = {}
    v['boundaries'] = ''.join(
        f'<tr><th scope="row">{MODES.get(mode, esc(mode))} <code>{esc(mode)}</code></th><td><code>{pc}</code></td><td>{MODELS.get(role, esc(role))}</td></tr>'
        for mode, apis in replay['modeled_apis'].items() for pc, role in apis.items())
    v['function_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(" / ".join(f["names"]))}</code></th><td>MAIN</td><td><code>{f["address"]}</code></td>'
        f'<td class="n">{n(f["size"])}</td><td>{f["segment"]}</td></tr>' for f in source['main_functions'])
    v['function_rows'] += (
        f'<tr><th scope="row"><code>{esc(" / ".join(e01["names"]))}</code></th><td>E01</td><td><code>{e01["address"]}</code></td>'
        f'<td class="n">{n(e01["size"])}</td><td>{e01["segment"]}</td></tr>')
    v['word_rows'] = ''.join(
        f'<tr><th scope="row">{WORD_ROLES.get(g["role"], esc(g["role"]))}</th><td>{space}</td><td class="n">{len(g["words"])}</td></tr>'
        for space, groups in (('MAIN', source['main_words']), ('E01', source['e01_words'])) for g in groups)
    v['handle_rows'] = ''.join(
        f'<tr><th scope="row"><code>+{offset}</code></th><td><code>{value:#x}</code></td></tr>' for offset, value in first['handle_fields'].items())
    v['different_words'] = n(compare['words'] - compare['byte_identical_words'])
    v['host_ack_sha256'] = functions['HostAck']['sha256']
    v['header_sha256'] = replay['fixture']['update_header']['sha256']
    v['installed_sha256'] = replay['fixture']['installed_header']['sha256']
    v['k3_commit'] = read('update-service.json')['comparison']['commit']
    page = (ROOT/'analysis/main-burn-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'main-burn-prefix-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built main-burn-prefix-report.html')


if __name__ == '__main__':
    main()
