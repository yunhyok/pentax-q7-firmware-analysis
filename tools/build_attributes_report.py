"""Render captured font attributes, the separately configured scaled draw and
the conditional native context selection."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses

KIND = {7: '글자 크기 (폭, 높이)', 12: '글자 간격', 4: '글자 색 (팔레트 슬롯 1)'}
STAGE = {'refresh': '갱신 요청 기록', 'raster_setup': '화면 준비', 'font_load_and_draw': '글꼴 로딩·그리기'}
LETTERS = 'sRGB'


def scale_svg(original, scaled):
    """Glyph boxes at their x positions; horizontal 5x, vertical 1:1."""
    def X(x):
        return 150 + (x - 96) * 5
    rows = []
    for row, (label, cls, y, items) in enumerate((('기본 64×48', 'ok', 30, original), ('48×48 축소', 'key', 120, scaled))):
        rows.append(f'<text class="t" x="8" y="{y + 30}">{label}</text>')
        for i, (x, w) in enumerate(items):
            rows.append(f'<rect class="b {cls}" x="{X(x)}" y="{y}" width="{w * 5}" height="48" rx="4"/>'
                        f'<text class="t mid" x="{X(x) + w * 5 / 2:g}" y="{y + 21}">{LETTERS[i]}</text>'
                        f'<text class="s mid" x="{X(x) + w * 5 / 2:g}" y="{y + 39}">폭 {w}</text>'
                        f'<text class="n mid" x="{X(x)}" y="{y + 64}">{x}</text>')
    end = original[-1][0] + original[-1][1]
    rows.append(f'<text class="n mid" x="{X(end)}" y="94">{end}</text>')
    send = scaled[-1][0] + scaled[-1][1]
    rows.append(f'<text class="n mid" x="{X(send)}" y="184">{send}</text>')
    return ('<svg class="dg" viewBox="0 0 800 210" role="img" aria-labelledby="dg-attr-scale-title dg-attr-scale-desc">'
            '<title id="dg-attr-scale-title">기본 크기와 48×48 축소의 글자 위치 비교</title>'
            '<desc id="dg-attr-scale-desc">위 줄은 기본 크기로 그린 sRGB 네 글자로, x 96·120·149·183에서 폭 24·29·34·29입니다. '
            '아래 줄은 48×48 속성을 적용한 축소 그리기로, x 96·114·135·160에서 폭 18·21·25·21입니다. 높이는 둘 다 48입니다. '
            '그림은 가로를 5배로 늘렸습니다.</desc>'
            + ''.join(rows) +
            '<text class="n" x="8" y="204">가로 5배 확대. 숫자는 각 글자의 시작 x와 끝 x(논리 좌표)입니다. 높이 48·y = 64는 두 줄이 같습니다.</text></svg>')


def event_text(e, names):
    k = e['kind']
    if k == 'attribute-setter':
        return f'크기 속성 → {names[e["context"]]}'
    if k == 'text-render-entry':
        return f'글자 → {names[e["context"]]}'
    if k == 'cache':
        return '캐시 요청'
    if k == 'publish':
        return f'표시 요청 ID {e["id"]}'
    if k == 'native-active-store':
        return f'<strong>활성 포인터 ← {names[e["context"]]}</strong>'
    if k == 'fallback-log':
        return '빈 슬롯 진단'
    return esc(k)


def main():
    data = read('colorspace-attributes.json')
    binding = read('context-binding.json')
    glyph = read('colorspace-glyph.json')
    br = data['bounded_replay']
    refresh = br['refresh']
    scaled = br['scaled']
    v = {}
    v['refresh_count'] = str(refresh['case_count'])
    v['attr_events'] = str(refresh['event_counts']['attribute'])
    v['text_events'] = str(refresh['event_counts']['text'])
    v['frame_bytes'] = f'{data["scale_oracle"]["frame_bytes"]:,}'
    v['guard'] = str(data['scale_oracle']['guard_bytes_per_end'])
    groups = refresh['srgb_groups']
    v['widget'] = data['input_reference']['widget']
    v['draw_ids'] = '·'.join(str(g[0]['args'][0]) for g in groups)
    cap = []
    for i, e in enumerate(groups[0]):
        a = e['args']
        if e['kind'] == 'attribute':
            cap.append(f'<tr><th scope="row">{i + 1}</th><td>속성 · 그리기 ID {a[0]}</td><td><code>{a}</code></td><td>{KIND.get(a[1], a[1])}</td></tr>')
        else:
            cap.append(f'<tr><th scope="row">{i + 1}</th><td>글자 · ID {a[0]}</td><td><code>{a[0]}, {a[1]:#x}, …, {a[3]}, {a[4]}, {a[5]}, {a[6]}</code></td>'
                       f'<td>(x, y) = ({a[3]}, {a[4]}), 글자 {a[5]}개</td></tr>')
    v['capture_rows'] = ''.join(cap)
    v['prior_sha'] = refresh['prior_refresh_sha256']
    v['ordered_sha'] = refresh['ordered_event_sha256']
    v['rows'] = ''.join(f'<tr><th scope="row">{r["kind"]} · {KIND.get(r["kind"], "")}</th><td><code>{r["table_word"]}</code></td>'
                        f'<td><code>{r["case_entry"]}</code></td><td><code>{r["callee"]}</code></td><td>{esc("; ".join(r["writes"]))}</td></tr>'
                        for r in data['attribute_dispatch'])
    controls = {d['vex_block_events'] for d in br['dispatch']}
    assert len(controls) == 1
    v['control_events'] = str(controls.pop())
    original = [(c['x'], c['width']) for c in glyph['bounded_replay']['cases'][1]['renderer_calls']]
    small = [(c['args'][3], c['args'][7]) for c in scaled['renderer_calls']]
    assert [w for _, w in original] == [c['args'][5] for c in scaled['renderer_calls']]
    v['scale_svg'] = scale_svg(original, small)
    v['scaled_entry'] = scaled['entry']
    v['scaled_return'] = str(scaled['return_value'])
    v['scaled_events'] = f'{scaled["vex_block_events"]:,}'
    hist = scaled['indexed_histogram']
    assert hist['1'] + hist['2'] == scaled['changed_bytes']
    v['changed'] = f'{scaled["changed_bytes"]:,}'
    v['hist1'] = f'{hist["1"]:,}'
    v['hist2'] = f'{hist["2"]:,}'
    v['frame_sha'] = scaled['frame_sha256']
    rows = []
    for stage, apis in br['modeled_boundaries'].items():
        if stage == 'staged':
            for sub, inner in apis.items():
                rows += [(STAGE.get(sub, sub), pc, t) for pc, t in inner.items()]
        else:
            rows += [(STAGE.get(stage, stage), pc, t) for pc, t in apis.items()]
    v['boundaries'] = ''.join(f'<tr><th scope="row">{esc(s)}</th><td><code>{pc}</code></td><td>{esc(t)}</td></tr>' for s, pc, t in rows)
    v['words'] = str(len(list(witnesses(data))))
    v['functions'] = str(len(data['selected_functions']))
    v['function_names'] = ', '.join(f'<code>{"/".join(f["names"])}</code>' for f in data['selected_functions'])
    # Conditional native context selection.
    rp = binding['bounded_replay']['replay']
    names = {rp['seed']['contexts']['17']: 'A', rp['seed']['contexts']['18']: 'B'}
    brows = [f'<tr><th scope="row">시작</th><td>{rp["seed"]["initial_draw"]}</td><td>{event_text(rp["initial_binding"], names)}</td></tr>']
    for i, roll in enumerate(rp['valid_rolls']):
        brows.append(f'<tr><th scope="row">교대 {i + 1}</th><td>{roll["draw_before"]} → {roll["draw_after"]}</td>'
                     f'<td>{" → ".join(event_text(e, names) for e in roll["events"])}</td></tr>')
    ms = rp['missing_slot']
    brows.append(f'<tr><th scope="row">슬롯 18 비움</th><td>17 → {ms["draw_after"]}</td>'
                 f'<td>{" → ".join(event_text(e, names) for e in ms["events"])} (교대 뒤 활성: {names[ms["active_after"]]})</td></tr>')
    v['binding_rows'] = ''.join(brows)
    c = binding['contracts']
    label = {'screen_draw_id': '화면 그리기 ID', 'screen_show_id': '화면 표시 ID', 'normal_roll_gate': '정상 교대 조건',
             'registry_pointer_global': '등록 테이블 포인터 전역', 'original_registry_pointer': '원본 등록 테이블',
             'registry_slot': '슬롯 위치', 'active_draw_context': '활성 그리기 컨텍스트', 'show_context': '표시 컨텍스트',
             'max_id_global': '최대 ID 전역', 'initial_max_id': '초기 최대 ID', 'layer_ranges_global': '레이어 범위 전역',
             'initial_inclusive_layer_ranges': '초기 레이어 범위', 'draw_parameter': '그리기 매개변수',
             'parameter_jump_word_va': '매개변수 점프표 워드', 'draw_setter': '그리기 버퍼 설정 함수',
             'active_store_pc': '활성 포인터 저장 명령', 'active_store_vex_pc': 'VEX가 기록한 저장 위치'}
    v['contracts'] = ''.join(f'<dt>{label.get(k, esc(k))}</dt><dd><code>{esc(str(val))}</code></dd>' for k, val in c.items())
    v['binding_models'] = ''.join(f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(t)}</td></tr>' for pc, t in rp['models'].items())
    v['binding_functions'] = str(len(binding['source']['selected_functions']))
    v['binding_words'] = str(sum(len(e['words']) for e in binding['source']['evidence']))
    v['binding_cap'] = f'{rp["step_cap_per_call"]:,}'
    v['k3_commit'] = glyph['comparison'][0]['commit']
    page = (ROOT/'analysis/attributes-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'colorspace-attributes-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built colorspace-attributes-report.html')


if __name__ == '__main__':
    main()
