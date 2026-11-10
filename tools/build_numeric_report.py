"""Render the C recompilation and fixed-slot repacking report (recompiled-numeric-report.html).

The prose and the diagrams live in analysis/numeric-template.html. This builder supplies the
tables, hashes and counts from analysis/recompiled-numeric.json, and checks that the values quoted
in the static prose and diagrams still match that evidence.
"""
from collections import Counter

from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

INPUTS = {
    'identity-left': ('왼쪽이 단위 행렬', '곱해도 오른쪽 행렬이 그대로 나오는지'),
    'identity-right': ('오른쪽이 단위 행렬', '곱해도 왼쪽 행렬이 그대로 나오는지'),
    'zero': ('왼쪽이 영 행렬', '결과가 모두 0인지'),
    'positive-wrap': ('모든 원소가 −32,768', '곱의 합이 32비트 부호 범위를 넘을 때'),
    'negative-wrap': ('32,767과 −32,768', '곱의 합이 음수 쪽으로 넘을 때'),
    'positive-half-step': ('1 × 4,095·4,096·4,097', '양수 쪽 반올림 경계'),
    'negative-half-step': ('−1 × 4,095·4,096·4,097', '음수 쪽 반올림 경계'),
    'low-halfword-wrap': ('−32,768 × (−32,768, 32,767, 8,192)', '결과가 16비트를 넘어 하위 16비트만 남을 때'),
}
LAYOUTS = {
    'distinct': '세 버퍼가 서로 떨어져 있음',
    'out-is-left': '출력이 왼쪽 입력과 같은 버퍼',
    'out-is-right': '출력이 오른쪽 입력과 같은 버퍼',
    'out-overlaps-left-after': '출력이 왼쪽 입력과 일부 겹침',
    'out-overlaps-right-before': '출력이 오른쪽 입력과 일부 겹침',
    'both-inputs-are-same': '두 입력이 같은 버퍼',
    'all-three-are-same': '세 버퍼가 모두 같음',
    'three-partial-overlaps': '세 버퍼가 서로 일부씩 겹침',
}
COLOR_SPACES = {0: 'sRGB (0)', 1: 'AdobeRGB (1)'}
WORD_ROLES = {
    'Input snapshot and O32 entry': '입력을 스택에 복사하는 부분과 o32 진입',
    'Signed multiply, low word, rounding, shift and halfword output': '부호 있는 곱셈, 하위 워드, 반올림, 시프트, 16비트 저장',
    'Original caller and both color-space routes': '원본 호출 함수와 두 색공간의 경로',
}


def n(value):
    return f'{value:,}'


def code(value):
    return f'<code>{esc(value)}</code>'


def main():
    data = read('recompiled-numeric.json')
    r, build = data['replay'], data['replay']['build']
    attempt, package = data['package_attempt'], data['package_rebuild']
    first, second = package['blocks']

    # Values that the template quotes as fixed text in prose and diagrams.
    assert (r['leaf_case_count'], r['caller_case_count'], r['substituted_calls']) == (96, 4, 58)
    assert r['ordered_leaf_store_count_per_image'] == 864 == 96 * 9
    assert (build['text_size'], r['original']['bytes'], r['original']['unchanged_tail_bytes']) == (164, 236, 72)
    assert (r['original']['entry'], r['original']['end_exclusive'], r['original']['caller_entry']) == ('0x8041bc90', '0x8041bd7c', '0x8041c180')
    assert build['compiler_version'] == '0.15.2' and build['llvm_build'].startswith('clang version 20.1.2 ')
    elf = build['elf']
    assert (elf['flags'], elf['isa_revision'], elf['fp_abi_attribute'], elf['unresolved_imports'], elf['code_relocations']) == ('0x70001001', 2, 1, 0, 0)
    assert r['original']['carrier_e_flags'] == '0x70001001' and r['original']['carrier_fp_abi_attribute'] is None
    assert 0x70001001 == 0x70000000 | 0x00001000 | 0x00000001
    boundary = [name for name in INPUTS]
    cases = Counter(c['case'] for c in r['leaf_cases'])
    layouts = Counter(c['layout'] for c in r['leaf_cases'])
    assert all(cases[name] == 8 for name in boundary) and sum(v for k, v in cases.items() if k.startswith('random-')) == 32
    assert list(layouts) == list(LAYOUTS) and set(layouts.values()) == {12}
    assert [len(c['call_sites']) for c in r['caller_cases']] == [14, 15, 14, 15]
    assert [c['nonstack_stores'] for c in r['caller_cases']] == [210] * 4
    probe = r['machine_state_probe']
    assert (probe['original_hi'], probe['original_lo'], probe['recompiled_hi'], probe['recompiled_lo']) == (0, 0xC0000000, 0, 0)
    assert probe['outputs_equal'] and probe['output_bytes'] == 18 and probe['original_caller_mfhi_mflo_addresses'] == []
    assert (attempt['needed_bits'], attempt['needed_bytes'], attempt['capacity_bytes'], attempt['output_written']) == (79323, 9916, 9856, False)
    assert attempt['needed_bytes'] - attempt['capacity_bytes'] == 60 and attempt['block'] == first['block'] == 154
    assert (first['original_bits'], first['new_bits'], first['used_bytes'], first['zero_tail_bits'], first['capacity_bytes']) == (77993, 78817, 9853, 31, 9856)
    assert (second['block'], second['original_bits'], second['new_bits'], second['used_bytes'], second['zero_tail_bits']) == (155, 78770, 78813, 9852, 35)
    assert first['capacity_bytes'] * 8 == 78848 == first['new_bits'] + first['zero_tail_bits'] == second['new_bits'] + second['zero_tail_bits']
    assert (first['windows'], first['repaired_tokens'], first['replaced_tokens'], first['new_copy_tokens'], first['new_cross_block_copy_tokens'], second['repaired_tokens']) == (21, 95, 102, 48, 16, 1)
    assert (package['total_blocks'], package['unchanged_blocks'], package['segments']) == (448, 446, 4)
    assert (package['patch_bytes'], package['decoded_difference_bytes'], package['output_size']) == (164, 142, 18743520)
    assert package['image_equals_replayed_overlay'] and package['all_decoded_bytes_and_layout_verified']
    footer = package['footer_after']
    assert footer['sum_matches'] and footer['stored_sum'] == footer['calculated_sum']
    words = len(list(witnesses(data)))
    assert words == 35 and len(data['selected_functions']) == 7

    v = {}
    v['input_rows'] = ''.join(
        f'<tr><th scope="row">{INPUTS[name][0]} {code(name)}</th><td>{INPUTS[name][1]}</td><td class="n">{cases[name]}</td></tr>'
        for name in boundary)
    v['layout_rows'] = ''.join(
        f'<tr><th scope="row">{LAYOUTS[name]} {code(name)}</th><td class="n">{count}</td></tr>' for name, count in layouts.items())
    v['rows'] = ''.join(
        f'<tr><th scope="row">{COLOR_SPACES[c["color_space"]]}</th><td class="n">{c["style"]}</td><td class="n">{c["hue"]}</td>'
        f'<td class="n">{c["saturation"]}</td><td class="n">{len(c["call_sites"])}</td><td class="n">{c["nonstack_stores"]}</td>'
        f'<td>{", ".join(code(hex(site)) for site in sorted(set(c["call_sites"])))}</td></tr>'
        for c in r['caller_cases'])
    v['block_rows'] = ''.join(
        f'<tr><th scope="row">{b["segment"]} 블록 {b["block"]}</th><td><code>{b["file_offset"]:#x}</code>~<code>{b["file_end"]:#x}</code></td>'
        f'<td>{code(b["virtual_address"])}~{code(b["virtual_end"])}</td><td class="n">{n(b["original_bits"])}</td>'
        f'<td class="n">{n(b["new_bits"])}</td><td class="n">{n(b["used_bytes"])}</td><td class="n">{b["zero_tail_bits"]}</td>'
        f'<td class="n">{b["repaired_tokens"]}</td></tr>' for b in package['blocks'])
    v['function_rows'] = ''.join(
        f'<tr><th scope="row">{code(f["name"])}</th><td><code>{f["address"]:#x}</code>~<code>{f["candidate_end"]:#x}</code></td>'
        f'<td class="n">{n(f["size"])}</td><td>{code(f["sha256"][:16] + "…")}</td></tr>' for f in data['selected_functions'])
    v['word_rows'] = ''.join(
        f'<tr><th scope="row">{WORD_ROLES.get(e["role"], esc(e["role"]))}</th><td class="n">{len(e["words"])}</td></tr>'
        for e in data['evidence'])
    arguments, tokens = [], iter(['zig'] + build['command'][1:])
    for token in tokens:
        # Keep an option and its value on one line.
        arguments.append(f'{token} {next(tokens)}' if token in ('-target', '-x', '-o') else token)
    lines, line = [], ''
    for token in arguments:
        if line and len(line) + len(token) + 1 > 62:
            lines.append(line)
            line = '  ' + token
        else:
            line = f'{line} {token}' if line else token
    lines.append(line)
    v['command'] = esc(' \\\n'.join(lines))
    v['source_sha'], v['object_sha'], v['text_sha'] = build['source_lf_sha256'], build['object_sha256'], build['text_sha256']
    v['compiler_sha'], v['archive_sha'] = build['compiler_exe_sha256'], build['windows_archive_sha256']
    v['llvm_build'] = esc(build['llvm_build'])
    v['original_sha'], v['caller_sha'] = r['original']['sha256'], r['original']['caller_sha256']
    v['output_sha'], v['rebuilt_elf_sha'], v['decoded_sha'] = package['output_sha256'], package['analysis_elf_sha256'], package['decoded_e04_sha256']
    v['analysis_elf_sha'] = data['analysis_elf_sha256']
    v['footer_sum'] = n(footer['stored_sum'])
    v['words'] = str(words)
    v['engine'] = esc(r['engine'])
    v['k3_commit'] = data['comparison']['commit']
    page = (ROOT/'analysis/numeric-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'recompiled-numeric-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built recompiled-numeric-report.html')


if __name__ == '__main__':
    main()
