"""Build the Q7 Color Space UI report from its evidence JSON and template."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

ROLE = {'title': '제목', 'sRGB option': 'sRGB 선택지', 'AdobeRGB option': 'AdobeRGB 선택지',
        'sRGB guide': 'sRGB 안내문', 'AdobeRGB guide': 'AdobeRGB 안내문', 'cancel': '취소', 'OK': '확정(OK)'}
NAME = {0: 'sRGB', 1: 'AdobeRGB'}


def cell(step):
    if step is None:
        return '<td>—</td>'
    return f'<td>{step["getter"]} <small class="muted">(쓰기 {len(step["setting_byte_stores"])})</small></td>'


def case_row(case):
    steps = {s['action']: s for s in case['steps']}
    end = steps.get('confirm') or steps.get('cancel')
    verb = '확정' if 'confirm' in steps else '취소'
    if case['initial'] == case['selected']:
        label = f'{NAME[case["initial"]]} 그대로 {verb}'
    else:
        label = f'{NAME[case["initial"]]} → {NAME[case["selected"]]}, {verb}'
    total = sum(len(s['setting_byte_stores']) for s in case['steps'])
    return (f'<tr><th scope="row">{label}</th>{cell(steps.get("open"))}{cell(steps.get("choose"))}'
            f'{cell(end)}{cell(steps.get("reopen"))}<td class="n">{total}</td></tr>')


def main():
    ui = read('colorspace-ui.json')
    replay = ui['replay']
    v = {}
    v['cases'] = ''.join(case_row(c) for c in replay['cases'])
    v['case_count'] = str(replay['case_count'])
    v['setter_calls'] = str(replay['setter_call_count'])
    v['stores'] = str(replay['setting_byte_store_count'])
    v['step_count'] = str(sum(len(c['steps']) for c in replay['cases']))
    v['labels'] = ''.join(f'<tr><th scope="row">{ROLE.get(r["role"], esc(r["role"]))}</th><td><code>{r["widget"]}</code></td>'
                          f'<td><code>{r["language_table"]}</code></td></tr>' for r in ui['rendering']['labels'])
    v['hooks'] = ''.join(f'<tr><th scope="row"><code>{a}</code></th><td>{esc(t)}</td></tr>'
                         for a, t in replay['modeled_boundaries'].items())
    v['hook_count'] = str(len(replay['modeled_boundaries']))
    v['words'] = str(len(list(witnesses(ui))))
    v['functions'] = str(len(ui['selected_functions']))
    v['k3_commit'] = ui['sources']['semantic_contract']['commit']
    page = (ROOT/'analysis/colorspace-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'colorspace-ui-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built colorspace-ui-report.html')


if __name__ == '__main__':
    main()
