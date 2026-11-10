"""Render the Color Space draw-path report from its evidence JSON and template."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

ROLE = {'title': '제목', 'sRGB option': 'sRGB 선택지', 'AdobeRGB option': 'AdobeRGB 선택지',
        'sRGB guide': 'sRGB 안내문', 'AdobeRGB guide': 'AdobeRGB 안내문', 'cancel': '취소', 'OK': '확정(OK)'}
PART = ['위', '왼쪽', '아래', '오른쪽', '안쪽']
SHAPE_CLASS = {0x4d: 'key', 0x4f: 'static', 0x4e: 'mute'}
Y_SCALE = 2.5


def highlight_svg(commands):
    """Draw the five captured rectangles in request order: x at 1:1, y stretched."""
    x0, y0, top = 40, 34, commands[0][1]
    parts = []
    for i, (x, y, w, h, index, _style) in enumerate(commands):
        parts.append(f'<rect class="b {SHAPE_CLASS[index]}" x="{x0 + x}" y="{y0 + (y - top) * Y_SCALE:g}" '
                     f'width="{w}" height="{h * Y_SCALE:g}"/>')
    bottom = y0 + 48 * Y_SCALE
    inner = commands[4]
    ty = y0 + (inner[1] - top) * Y_SCALE
    labels = (
        f'<text class="t" x="{x0 + 96}" y="{ty + 34:g}">선택지 글자 시작점 (96, {top})</text>'
        f'<text class="s" x="{x0 + 96}" y="{ty + 58:g}">안쪽: ({inner[0]}, {inner[1]}) 폭 {inner[2]} 높이 {inner[3]} · 번호 0x{inner[4]:02x}</text>'
        f'<text class="n" x="{x0}" y="{y0 - 10}">x = 0</text>'
        f'<text class="n end" x="{x0 + 720}" y="{y0 - 10}">x = 720</text>'
        f'<text class="n" x="{x0}" y="{bottom + 22:g}">y = {top}부터 높이 48 (세로 {Y_SCALE:g}배 확대). 위 6·아래 4·좌우 4 단위의 테두리와 안쪽을 요청 순서대로 겹쳐 그렸습니다.</text>')
    height = int(bottom + 36)
    return (f'<svg class="dg" viewBox="0 0 800 {height}" role="img" aria-labelledby="dg-render-hl-title dg-render-hl-desc">'
            '<title id="dg-render-hl-title">선택 강조를 이루는 사각형 다섯 개</title>'
            '<desc id="dg-render-hl-desc">폭 720, 높이 48인 강조 영역을 사각형 다섯 개로 그립니다. 위쪽 720×6과 왼쪽 4×44는 팔레트 번호 0x4d, '
            '아래쪽 720×4와 오른쪽 4×44는 0x4f, 마지막으로 안쪽 712×40을 0x4e로 칠합니다. 안쪽이 마지막에 칠해지므로 위쪽 테두리의 아래 두 줄은 안쪽 색으로 덮입니다. '
            '그림의 세로는 2.5배로 늘렸고 색은 번호를 구분하기 위한 것입니다.</desc>'
            + ''.join(parts) + labels + '</svg>')


def main():
    data = read('colorspace-render.json')
    replay = data['replay']
    cases = replay['refresh_cases']
    roles = {int(l['widget'], 16): ROLE.get(l['role'], esc(l['role'])) for l in data['labels']}
    icon = replay['icon']
    tables = data['focus_assets']['marker_tables']
    v = {}
    v['refresh_count'] = str(len(cases))
    v['text_lines'] = str(replay['total_text_lines'])
    assert replay['total_text_lines'] == sum(len(c['text']) for c in cases)
    v['shape_count'] = str(sum(len(c['frame_commands']) for c in cases))
    v['marker_bytes'] = str(replay['pixel_cases'][0]['changed_bytes'])
    v['rows'] = ''.join(
        f'<tr><th scope="row">{i + 1}</th><td>{"영어" if c["locale"] == 0 else "프랑스어"}</td>'
        f'<td>{"—" if c["key"] is None else c["key"]}</td><td>{"sRGB" if c["setting"] == 0 else "AdobeRGB"}</td>'
        f'<td class="n">{len(c["text"])}</td><td>{c["draw_before"]} → {c["draw_after"]}</td>'
        f'<td>{c["show_before"]} → {c["show_after"]}</td></tr>' for i, c in enumerate(cases))
    v['highlight_svg'] = highlight_svg(cases[0]['frame_commands'])
    v['y_scale'] = f'{Y_SCALE:g}'
    v['shape_rows'] = ''.join(
        f'<tr><th scope="row">{i + 1}</th><td>{PART[i]}</td><td class="n">{x}</td><td class="n">{y}</td>'
        f'<td class="n">{w}</td><td class="n">{h}</td><td><code>0x{index:02x}</code></td></tr>'
        for i, (x, y, w, h, index, _s) in enumerate(cases[0]['frame_commands']))
    v['text_rows'] = ''.join(
        f'<tr><th scope="row">{i + 1}</th><td>{roles.get(t["widget"], hex(t["widget"]))} <code>{t["widget"]:#x}</code></td>'
        f'<td>({t["xy"][0]}, {t["xy"][1]})</td><td class="n">{t["glyph_units"]}</td>'
        f'<td><code>{t["staged_sha256"][:16]}…</code></td></tr>'
        for i, c in enumerate(cases) for t in c['text'])
    v['pixel_rows'] = ''.join(
        f'<tr><th scope="row">({p["xy"][0]}, {p["xy"][1]})</th><td class="n">{p["changed_bytes"]}</td>'
        f'<td><code class="wrap">{p["frame_sha256"]}</code></td></tr>' for p in replay['pixel_cases'])
    v['icon_compressed'] = str(icon['compressed_bytes'])
    v['icon_decoded'] = f'{icon["bitmap_size"][0] * icon["bitmap_size"][1]:,}'
    v['icon_bitmap'] = f'{icon["bitmap_size"][0]}×{icon["bitmap_size"][1]}'
    v['icon_logical'] = f'{icon["logical_size"][0]}×{icon["logical_size"][1]}'
    v['icon_stride'] = str(icon['synthetic_stride'])
    v['icon_height'] = str(icon['synthetic_height'])
    v['icon_fill'] = str(icon['initial_palette_index'])
    v['icon_va'] = icon['compressed_va']
    v['icon_sha'] = icon['compressed_sha256']
    v['icon_decoded_sha'] = icon['decoded_sha256']
    v['t_lw'], v['t_h'] = tables['logical_width_u16'], tables['height_u16']
    v['t_bw'], v['t_rle'] = tables['bitmap_width_u16'], tables['rle_offset_u32']
    v['cache_bytes'] = f'{cases[0]["cache_range"][1]:,}'
    assert cases[0]['cache_range'][1] == 960 * 480
    v['hooks'] = ''.join(f'<tr><th scope="row"><code>{a}</code></th><td>{esc(t)}</td></tr>'
                         for a, t in replay['modeled_boundaries'].items())
    v['hook_count'] = str(len(replay['modeled_boundaries']))
    v['words'] = str(len(list(witnesses(data))))
    v['functions'] = str(len(data['selected_functions']))
    ranges = []

    def walk(o):
        if isinstance(o, dict):
            if 'sha256' in o and 'length_bytes' in o:
                ranges.append(o)
            for x in o.values():
                walk(x)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(data['labels'])
    walk(data['focus_assets'])
    v['resource_ranges'] = str(len(ranges))
    v['k3_commit'] = data['references'][1]['commit']
    page = (ROOT/'analysis/render-template.html').read_text(encoding='utf-8')
    for k, value in v.items():
        page = page.replace('{{'+k+'}}', value)
    assert '{{' not in page
    (ROOT/'colorspace-render-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built colorspace-render-report.html')


if __name__ == '__main__':
    main()
