"""Build the HDR output-selection and FC1 coefficient report (final-color-report.html)."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

# ITU-R BT.601-7 section 2.5: E'Y = 0.299R + 0.587G + 0.114B, E'CB = (B-Y)/1.772, E'CR = (R-Y)/1.402.
# Used only as an external reference row next to the firmware values; nothing below depends on it.
_KR, _KG, _KB = 0.299, 0.587, 0.114
BT601 = [
    [_KR, _KG, _KB],
    [-_KR / 1.772, -_KG / 1.772, (1 - _KB) / 1.772],
    [(1 - _KR) / 1.402, -_KG / 1.402, -_KB / 1.402],
]

CASE_LABELS = {
    'hdr-custom-flag0': 'HDR 계수 · 제어 비트 0',
    'hdr-custom-flag1': 'HDR 계수 · 제어 비트 1',
    'signed-boundary-custom': '부호 경계값(임의 계수)',
    'mode1-null-601': 'mode 1 · 포인터 없음 → 내장 601',
    'mode1-null-709': 'mode 1 · 포인터 없음, 선택값 1 → 내장 709',
    'mode3-null-unity': 'mode 3 · 포인터 없음 → 단위 행렬',
}
SUBMIT_LABELS = {
    'fresh_hdr_type0': '새 HDR 경로 (분석 대상)',
    'explicit_descriptor_id9_counterfactual': '비교: ID 9 대체 디스크립터를 넣은 경우',
}


def signed(v):
    return f'−{-v:,}' if v < 0 else f'{v:,}'


def main():
    v = {}
    submit = read('submit-followup.json')
    fiplib = read('fiplib-followup.json')
    checks = read('fiplib-coefficient-checks.json')

    # Output selection: the two bounded replay cases.
    v['submit_rows'] = ''.join(
        f'<tr><th scope="row">{SUBMIT_LABELS.get(c["name"], esc(c["name"]))}</th>'
        f'<td><code>{c["path_output"]}</code></td><td class="n">{c["selector"]}</td>'
        f'<td><code>{c["selector_destination"]}</code></td><td><code>{c["submitted_surface"]}</code></td>'
        f'<td class="n">{c["image_type"]}</td><td class="n">{c["image_kind"]}</td></tr>'
        for c in submit['replay']['cases'])
    v['submit_stubs'] = ''.join(
        f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(name)}</td></tr>'
        for pc, name in submit['replay']['stubs'].items())
    v['submit_stub_count'] = str(len(submit['replay']['stubs']))

    # The eleven HDR values and where each one travels.
    src = fiplib['hdr_case']['source']
    values = src['signed_halfwords']
    hdr_case = next(c for c in checks['cases'] if c['case'] == 'hdr-custom-flag0')
    mmio = hdr_case['expected_mmio']
    names = [f'계수 {i + 1}' for i in range(9)] + ['보조값 1', '보조값 2']
    v['value_rows'] = ''.join(
        f'<tr><th scope="row">{names[i]}</th><td><code>+{src["halfword_offsets"][i]}</code></td>'
        f'<td><code>+{src["fiplib_input_offsets"][i]}</code></td><td><code>+{0x100 + 4 * i:#x}</code></td>'
        f'<td><code>{mmio[i][0]:#x}</code></td><td class="n">{signed(values[i])}</td></tr>'
        for i in range(11))
    v['fc_word_addr'] = f'{mmio[11][0]:#x}'
    v['coef_first_addr'] = f'{mmio[0][0]:#x}'
    v['coef_last_addr'] = f'{mmio[10][0]:#x}'
    v['matrix'] = '\n'.join(' '.join(f'{signed(x):>7}' for x in values[r * 3:r * 3 + 3]) for r in range(3))
    v['companions'] = ', '.join(f'{x:,}' for x in values[9:])
    rows = ['Y (밝기)', 'Cb (청색 차)', 'Cr (적색 차)']
    v['bt601_rows'] = ''.join(
        f'<tr><th scope="row">{rows[r]}</th>'
        + ''.join(f'<td class="n">{signed(values[r * 3 + k])}</td>' for k in range(3))
        + ''.join(f'<td class="n">{values[r * 3 + k] / 2048:+.4f}</td>' for k in range(3))
        + ''.join(f'<td class="n">{BT601[r][k]:+.4f}</td>' for k in range(3)) + '</tr>'
        for r in range(3))
    v['bt601_maxdiff'] = f'{max(abs(values[r * 3 + k] - BT601[r][k] * 2048) for r in range(3) for k in range(3)):.2f}'

    # Six executed cases, ordered MMIO writes.
    v['numeric_rows'] = ''.join(
        f'<tr><th scope="row">{CASE_LABELS.get(c["case"], esc(c["case"]))}</th><td class="n">{c["mode"]}</td>'
        f'<td>{", ".join(signed(x) for x in c["expected_halfwords"])}</td>'
        f'<td class="n">{c["expected_mmio"][-1][2]}</td><td class="n">{len(c["expected_mmio"])}</td></tr>'
        for c in checks['cases'])
    v['case_count'] = str(len(checks['cases']))
    v['mmio_total'] = str(sum(len(c['expected_mmio']) for c in checks['cases']))
    v['writes_per_case'] = str(len(hdr_case['expected_mmio']))
    v['replayed_functions'] = ', '.join(f'<code>{a}</code>' for a in checks['functions'])

    docs = [submit, fiplib]
    v['function_count'] = str(len({f['address'] for d in docs for f in d['selected_functions']}))
    v['word_count'] = f"{sum(len(list(witnesses(d))) for d in docs):,}"
    c = read('final-comparison.json')
    v['k3_commit'] = esc(c['latest_main_commit_verified_via_gh_api'])
    v['k3_base'] = c['k3_public_remote'] + '/blob/' + v['k3_commit'] + '/analysis/'

    page = (ROOT / 'analysis/final-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{' + key + '}}', value)
    assert '{{' not in page
    (ROOT / 'final-color-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built final-color-report.html')


if __name__ == '__main__':
    main()
