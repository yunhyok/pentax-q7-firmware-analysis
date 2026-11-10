"""Render the selection-highlight raster report from its evidence JSON and template."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

CASE = {'srgb-highlight': 'sRGB 강조 (y = 64)', 'adobergb-highlight': 'AdobeRGB 강조 (y = 112)',
        'word-aligned': 'word 정렬 (폭 32, x 짝수)', 'halfword-aligned': 'halfword 정렬 (폭 16, x 짝수)',
        'odd-x-gdi': '홀수 x', 'gdi-clipped-edge': '오른쪽·아래 경계 잘림', 'zero-height': '높이 0'}
BRANCH = {'word': 'word', 'halfword': 'halfword', 'gdi': 'GDI'}
PART = ['위', '왼쪽', '아래', '오른쪽', '안쪽']


def command(c):
    x, y, w, h, index, _style = c
    return f'({x}, {y}, {w}, {h}, <code>0x{index:02x}</code>)'


def events(step):
    ev = step['vex_pixel_write_events']
    if not ev:
        return '없음'
    return ' · '.join(f'<code>{e["pc"]}</code> {e["size"]}B×{e["count"]:,}' for e in ev)


def main():
    data = read('colorspace-raster.json')
    replay = data['replay']
    cases = {c['name']: c for c in replay['cases']}
    srgb, adobe = cases['srgb-highlight'], cases['adobergb-highlight']
    assert [s['changed_bytes'] for s in srgb['steps']] == [s['changed_bytes'] for s in adobe['steps']]
    buf = replay['buffer']
    v = {}
    v['frame_bytes'] = f'{buf["stride"] * buf["height"]:,}'
    v['fill'] = str(buf['fill'])
    v['highlight_bytes'] = f'{srgb["steps"][-1]["changed_bytes"]:,}'
    v['case_count'] = str(len(replay['cases']))
    v['step_rows'] = ''.join(
        f'<tr><th scope="row">{i + 1} {PART[i]}</th><td>{command(s["command"])}</td><td>{BRANCH[s["branch"]]}</td>'
        f'<td class="n">{s["changed_bytes"]:,}</td><td>{events(s)}</td></tr>' for i, s in enumerate(srgb['steps']))
    v['rows'] = ''.join(
        f'<tr><th scope="row">{CASE.get(c["name"], esc(c["name"]))}</th>'
        f'<td>{"5개 (위 표)" if len(c["steps"]) > 1 else command(c["steps"][0]["command"])}</td>'
        f'<td>{" → ".join(BRANCH[s["branch"]] for s in c["steps"])}</td>'
        f'<td class="n">{c["steps"][-1]["changed_bytes"]:,}</td><td><code>{c["steps"][-1]["frame_sha256"][:16]}…</code></td></tr>'
        for c in replay['cases'])
    v['boundaries'] = ''.join(f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(text)}</td></tr>'
                              for pc, text in replay['modeled_boundaries'].items())
    v['hook_count'] = str(len(replay['modeled_boundaries']))
    v['fill_function'] = replay['context_fill_function']
    v['words'] = str(len(list(witnesses(data))))
    v['functions'] = str(len(data['selected_functions']))
    v['dup_count'] = str(len(data['duplicate_named_ranges']))
    role = {'generic indirect dispatch': '일반 간접 분배', '8-bit context renderer': '8비트 컨텍스트 렌더러'}
    rows = [f'<tr><th scope="row"><code>{d["name"]}</code> · {role.get(d["role"], esc(d["role"]))}</th><td><code>{d["va"]}</code></td>'
            f'<td class="n">{d["length_bytes"]}</td><td><code class="wrap">{d["sha256"]}</code></td></tr>'
            for d in data['duplicate_named_ranges']]
    t = data['context_template']
    rows.append(f'<tr><th scope="row"><code>sDcOsd8</code> 컨텍스트 템플릿</th><td><code>{t["va"]}</code></td>'
                f'<td class="n">{t["length_bytes"]:,}</td><td><code class="wrap">{t["sha256"]}</code></td></tr>')
    v['dup_rows'] = ''.join(rows)
    v['k3_commit'] = data['comparison'][0]['commit']
    page = (ROOT/'analysis/raster-template.html').read_text(encoding='utf-8')
    for k, value in v.items():
        page = page.replace('{{'+k+'}}', value)
    assert '{{' not in page
    (ROOT/'colorspace-raster-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built colorspace-raster-report.html')


if __name__ == '__main__':
    main()
