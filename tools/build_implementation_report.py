"""Render the offline rebuild, update-check, AF foundation and UI-boundary report.

The prose and the diagrams live in analysis/implementation-template.html. This builder only
supplies the values that come from the evidence JSON (table rows, counts, hashes) and checks
that the numbers quoted in the static diagrams still match that evidence.
"""
from build_deep_report import ROOT, read, esc

GATE_CASES = {
    'valid': ('정상 파일', '식별자 3개와 합계가 모두 맞음'),
    'wrong_code_name': ('첫째 식별자가 다름', '<code>ORION</code> 첫 바이트의 비트 하나를 뒤집음'),
    'wrong_kb_number': ('둘째 식별자가 다름', '<code>KB538</code> 첫 바이트의 비트 하나를 뒤집음'),
    'wrong_product_number': ('셋째 식별자가 다름', '<code>77690</code> 첫 바이트의 비트 하나를 뒤집음'),
    'wrong_checksum': ('합계가 다름', '저장된 합계 첫 바이트의 비트 하나를 뒤집음'),
    'version_bytes_changed': ('버전 4바이트만 다름', '마지막 4바이트를 모두 <code>0xff</code>로 바꿈'),
    'changed_body_unrepaired': ('본문을 바꾸고 합계는 그대로', '본문 첫 바이트를 바꾸고 합계는 고치지 않음'),
    'changed_body_repaired': ('본문을 바꾸고 합계를 다시 계산', '본문 첫 바이트를 바꾼 뒤 합계를 새로 적음'),
    'empty_size': ('파일 크기 0', '크기 조회 모델이 0을 돌려줌'),
    'open_failure': ('파일 열기 실패', '열기 모델이 0을 돌려줌'),
    'short_footer': ('꼬리표를 다 읽지 못함', '32바이트 읽기 모델이 31바이트만 돌려줌'),
    'allocation_failure': ('메모리 할당 실패', '할당 모델이 0을 돌려줌'),
    'short_body': ('본문을 다 읽지 못함', '본문 읽기 모델이 1바이트 모자라게 돌려줌'),
}
GATE_MODELS = {
    'file size': '파일 크기 조회', 'file open': '파일 열기', 'relative seek': '파일 위치 이동',
    'file read': '파일 읽기', 'file close': '파일 닫기', 'allocation': '메모리 할당',
    'free': '메모리 해제', 'diagnostic output': '진단 출력',
}


def n(value):
    return f'{value:,}'


def main():
    rebuild = read('rebuild-evidence.json')
    port = read('portability-evidence.json')
    round_trip = rebuild['roundtrip']
    package = round_trip['package_report']
    patch = rebuild['patch_experiment']
    patched = patch['package_report']
    changed = [(s['name'], b) for s in patched['segment_results'] for b in s['changed_blocks']]
    assert len(changed) == 1
    segment, block = changed[0]
    gate = rebuild['app_gate']
    boot = rebuild['boot_dispatch']
    replay = port['replay']

    # Numbers that the template's prose and diagrams quote as fixed text.
    assert round_trip['block_count'] == 448 and round_trip['token_count'] == 3652200
    assert package['output_size'] == patched['output_size'] == 18743520 and package['byte_identical']
    assert (segment, block['block'], block['repaired_tokens']) == ('E04', 146, 8)
    assert (block['original_bits'], block['new_bits']) == (85277, 85426)
    assert patch['replay_returns'] == [0, 1] and patch['patch_va'] == '0x803f0210'
    assert gate['footer_bytes'] == 32 and gate['identifiers'] == ['ORION', 'KB538', '77690']
    assert gate['footer_original_file_offset'] == '0x11e00c0' and len(gate['replay']['cases']) == 13
    assert (boot['header_original_file_offset'], boot['header_size'], boot['actual_kind']) == ('0x100000', 192, 3)
    assert len(boot['replay']['header_cases']) == 5
    assert len(replay['af_fit_cases']) == 6 and len(replay['geometry']['icon_sizes']) == 5
    assert replay['geometry']['reported_logical_size'] == [960, 480] and len(replay['icon_draw']['cases']) == 2
    assert replay['af_fit_cases'][2] == {'positions': [0, 2, 4, 6, 8], 'contrast': [75, 91, 99, 99, 91], 'expected': 5}

    v = {}
    v['segment_rows'] = ''.join(
        f'<tr><th scope="row">{esc(s["name"])}</th><td class="n">{n(s["blocks"])}</td><td class="n">{n(s["tokens"])}</td>'
        f'<td><code>{s["decoded_sha256"][:16]}…</code></td></tr>' for s in package['segment_results'])
    before, after = patched['footer_before'], patched['footer_after']
    v['patch_rows'] = ''.join(f'<tr><th scope="row">{name}</th><td>{value}</td></tr>' for name, value in (
        ('바꾼 위치', f'<code>{patch["patch_va"]}</code> — <code>GetFirmwareReleaseVersion</code>(<code>{patch["entry"]}</code>)의 <code>jr ra</code> 지연 슬롯'),
        ('명령 워드', f'<code>{patch["original_u32le_word"]}</code> → <code>{patch["replacement_u32le_word"]}</code>'),
        ('반환값', f'원본 {patch["replay_returns"][0]} → 변경 {patch["replay_returns"][1]}'),
        ('영향을 받은 블록', f'{segment}의 {block["block"]}번 블록 하나. 파일 구간 [{block["file_offset"]}, {block["file_end"]}) = {n(block["file_end"] - block["file_offset"])}바이트'),
        ('고친 토큰', f'{block["repaired_tokens"]}개'),
        ('압축 비트 수', f'{block["original_bits"]} → {block["new_bits"]}비트. 기존 저장 공간 안에 들어감'),
        ('꼬리표의 합계', f'{n(before["stored_sum"])} → {n(after["stored_sum"])} (다시 계산한 값과 일치)'),
        ('유지한 것', '파일 길이, 블록·세그먼트의 위치와 크기. 복원한 바이트를 모두 대조'),
    ))
    v['gate_rows'] = ''.join(
        f'<tr><th scope="row">{GATE_CASES.get(c["name"], (esc(c["name"]), ""))[0]}</th>'
        f'<td>{GATE_CASES.get(c["name"], ("", esc(c["name"])))[1]}</td><td class="n">{c["expected_return"]}</td></tr>'
        for c in gate['replay']['cases'])
    v['gate_models'] = ''.join(
        f'<tr><td><code>{pc}</code></td><td>{GATE_MODELS.get(role, esc(role))}</td></tr>'
        for pc, role in gate['replay']['modeled_functions'].items())
    names = {f['address']: f['name'] for f in rebuild['boot_selected_functions']}
    v['header_rows'] = ''.join(
        f'<tr><th scope="row">{c["kind"]}{" (실제 파일의 값)" if (c["kind"], c["header_hash_flag"]) == (boot["actual_kind"], boot["actual_hash_flag"]) else ""}</th>'
        f'<td class="n">{c["header_hash_flag"]}</td>'
        + (f'<td><code>{esc(names[int(c["burn_callback"], 16)])}</code> <code>{c["burn_callback"]}</code></td>' if c['accepted_handle']
           else '<td>선택 없음 (핸들을 만들지 않고 NULL 반환)</td>') + '</tr>'
        for c in boot['replay']['header_cases'])
    v['af_rows'] = ''.join(
        f'<tr><td class="n">{len(c["positions"])}</td><td>{", ".join(str(x) for x in c["positions"])}</td>'
        f'<td>{", ".join(str(x) for x in c["contrast"])}</td><td class="n">{c["expected"]}</td></tr>'
        for c in replay['af_fit_cases'])
    v['geometry_rows'] = ''.join(
        f'<tr><th scope="row">{r["icon_id"]}</th><td class="n">{r["layout_width"]} × {r["height"]}</td><td class="n">{r["data_width"]}</td></tr>'
        for r in replay['geometry']['icon_sizes'])
    checks = rebuild['validation']
    v['main_functions'] = str(checks['main_function_count'])
    v['boot_functions'] = str(checks['boot_typed_function_count'])
    v['main_words'] = str(checks['main_word_count'])
    v['boot_words'] = str(checks['boot_word_count'])
    v['file_words'] = str(checks['file_only_word_count'])
    v['port_functions'] = str(len(port['selected_functions']))
    v['port_words'] = str(sum(len(e['words']) for e in port['evidence']))
    v['input_sha256'] = rebuild['input_sha256']
    v['patched_sha256'] = patched['output_sha256']
    v['elf_sha256'] = package['analysis_elf_sha256']
    v['patched_elf_sha256'] = patched['analysis_elf_sha256']
    v['boot_sha256'] = rebuild['boot_image']['sha256']
    v['header_sha256'] = boot['header_sha256']
    v['k3_commit'] = port['comparison']['k3_artifact_reference_commit']
    page = (ROOT/'analysis/implementation-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'implementation-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built implementation-report.html')


if __name__ == '__main__':
    main()
