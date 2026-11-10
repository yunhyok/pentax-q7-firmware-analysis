"""Render the font-loading and indexed glyph evidence."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses


def main():
    data = read('colorspace-glyph.json')
    v = {}
    v['rows'] = ''.join(
        f'<tr><th scope="row">{"“sRGB” 네 글자 (텍스트 요청)" if len(c["units"])==4 else "글자 한 개 (직접 호출)"}</th>'
        f'<td><code>{c["entry"]}</code></td><td class="n">{c["changed_bytes"]:,}</td>'
        f'<td class="n">{c["vex_block_events"]:,}</td><td><code>{c["frame_sha256"][:16]}…</code></td></tr>'
        for c in data['bounded_replay']['cases'])
    v['words'] = str(len(list(witnesses(data))))
    v['functions'] = str(len(data['selected_functions']))
    stages = {'raster_setup': '화면 준비', 'font_load_and_draw': '글꼴 로딩·그리기'}
    v['boundaries'] = ''.join(
        f'<tr><th scope="row">{esc(stages.get(stage, stage))}</th><td><code>{pc}</code></td><td>{esc(description)}</td></tr>'
        for stage, apis in data['bounded_replay']['modeled_boundaries'].items() for pc, description in apis.items())
    v['k3_commit'] = data['comparison'][0]['commit']
    page = (ROOT/'analysis/glyph-template.html').read_text(encoding='utf-8')
    for key,value in v.items():
        page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    (ROOT/'colorspace-glyph-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built colorspace-glyph-report.html')


if __name__ == '__main__':
    main()
