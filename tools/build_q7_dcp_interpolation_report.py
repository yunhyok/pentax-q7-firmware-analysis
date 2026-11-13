"""Build the Q7 interpolation page after validating the complete research witness.

The sample table, the SDK source table, the neighbour diagram and the numbers quoted in the template come from
analysis/q7-dcp-interpolation.json and analysis/q7-dcp-interpolation-sources.json.
"""
import json
from html import escape
from pathlib import Path

from check_q7_dcp_interpolation import load_record, validate_report, canonical

ROOT = Path(__file__).resolve().parents[1]
SHORT = {'ProfileHueSatMapData1': 'HueSatMap 1', 'ProfileHueSatMapData2': 'HueSatMap 2', 'ProfileLookTableData': 'LookTable'}
SUP = str.maketrans('-0123456789', '⁻⁰¹²³⁴⁵⁶⁷⁸⁹')


def sci(x):
    if x == 0:
        return '0'
    mantissa, exponent = f'{x:.2e}'.split('e')
    return f'{mantissa}×10{str(int(exponent)).translate(SUP)}'


def stack(values):
    return '<br>'.join(f'{v:.9g}' for v in values)


def cell(dims, hsv):
    """Grid cell and fractional position of one HSV sample (same formulas as q7_dcp_interpolation_math)."""
    nh, ns, nv = dims
    h, s, v = hsv
    hp, sp, vp = h * nh / 360, s * (ns - 1), v * (nv - 1)
    h0, s0 = min(int(hp), nh - 1), min(int(sp), ns - 2)
    v0 = min(int(vp), nv - 2) if nv > 1 else 0
    return dict(h0=h0, s0=s0, v0=v0, hf=hp - h0, sf=sp - s0, vf=vp - v0, nh=nh, ns=ns, nv=nv)


def square(x, y, w, h, c, step, tag):
    """One H×S cell with the sample and the four corner weights."""
    px, py = x + c['hf'] * w, y + h - c['sf'] * h
    out = [f'<rect class="b mute" x="{x}" y="{y}" width="{w}" height="{h}" rx="2"/>',
           f'<path class="e open" d="M{px:.1f} {y + h}V{py:.1f}H{x}"/>']
    for dh, ds in ((0, 0), (1, 0), (0, 1), (1, 1)):
        cx, cy = x + dh * w, y + h - ds * h
        weight = (c['hf'] if dh else 1 - c['hf']) * (c['sf'] if ds else 1 - c['sf'])
        out.append(f'<rect class="b ok" x="{cx - 5}" y="{cy - 5}" width="10" height="10" rx="2"/>')
        tx = cx - 8 if dh else cx + 8
        ty = cy + 18 if ds else cy - 10
        out.append(f'<text class="n{" end" if dh else ""}" x="{tx}" y="{ty}">×{weight:.3f}</text>')
    out.append(f'<rect class="b key" x="{px - 6:.1f}" y="{py - 6:.1f}" width="12" height="12" rx="6"/>')
    out.append(f'<text class="n mid" x="{x}" y="{y + h + 18}">{c["h0"] * step:g}°</text>'
               f'<text class="n mid" x="{x + w}" y="{y + h + 18}">{(c["h0"] + 1) * step:g}°</text>')
    return ''.join(out), tag


def diagram(probe_input, map_dims, look_dims):
    m, k = cell(map_dims, probe_input), cell(look_dims, probe_input)
    h, s, v = probe_input
    left, _ = square(80, 92, 250, 170, m, 360 / map_dims[0], 'map')
    slice_a, _ = square(470, 112, 130, 130, k, 360 / look_dims[0], 'a')
    slice_b, _ = square(650, 112, 130, 130, k, 360 / look_dims[0], 'b')
    text = [
        '<text class="t" x="8" y="22">HueSatMap 90×30×1: 이웃 네 개</text>',
        f'<text class="s" x="8" y="44">H 칸 {m["h0"]}·{m["h0"] + 1}, S 칸 {m["s0"]}·{m["s0"] + 1} (명도 축 없음)</text>',
        f'<text class="n end" x="72" y="{92 + 170 + 4}">S {m["s0"]}/{m["ns"] - 1}</text>',
        f'<text class="n end" x="72" y="96">S {m["s0"] + 1}/{m["ns"] - 1}</text>',
        '<text class="t" x="420" y="22">LookTable 36×8×16: 이웃 여덟 개</text>',
        f'<text class="s" x="420" y="44">H 칸 {k["h0"]}·{k["h0"] + 1}, S 칸 {k["s0"]}·{k["s0"] + 1}, V 칸 {k["v0"]}·{k["v0"] + 1}</text>',
        f'<text class="s" x="470" y="90">V {k["v0"]}/{k["nv"] - 1}층 · ×{1 - k["vf"]:.3f}</text>',
        f'<text class="s" x="650" y="90">V {k["v0"] + 1}/{k["nv"] - 1}층 · ×{k["vf"]:.3f}</text>',
        f'<text class="n end" x="462" y="246">S {k["s0"]}/{k["ns"] - 1}</text>',
        f'<text class="n end" x="462" y="116">S {k["s0"] + 1}/{k["ns"] - 1}</text>',
        '<path class="e open" d="M410 60V300"/>',
        f'<text class="s" x="8" y="320">표본 H {h:g}°, S {s:g}, V {v:g}. 꼭짓점 숫자는 그 격자점의 가중치이며 합은 1입니다.</text>',
        '<text class="s" x="8" y="342">LookTable은 두 V층에서 각각 네 이웃을 섞은 뒤 층의 가중치로 다시 섞습니다.</text>',
    ]
    desc = (f'합성 표본 H {h:g}도, S {s:g}, V {v:g}가 두 표의 격자 안 어디에 놓이는지 그린 그림입니다. '
            f'왼쪽 HueSatMap(90×30×1)에서는 H 칸 {m["h0"]}과 {m["h0"] + 1}, S 칸 {m["s0"]}과 {m["s0"] + 1}로 둘러싸인 사각형 안에 표본이 있고 '
            '네 꼭짓점의 값을 가중 평균합니다. 명도 축은 칸이 하나뿐이라 보간하지 않습니다. '
            f'오른쪽 LookTable(36×8×16)에서는 V 칸 {k["v0"]}과 {k["v0"] + 1}의 두 층에서 각각 네 꼭짓점을 섞고, '
            f'두 층을 {1 - k["vf"]:.3f}와 {k["vf"]:.3f}의 비율로 다시 섞어 모두 여덟 이웃을 씁니다.')
    return ('<svg class="dg" viewBox="0 0 800 352" role="img" aria-labelledby="dg-grid-title dg-grid-desc">'
            '<title id="dg-grid-title">표본 하나가 놓인 격자 칸과 이웃 가중치</title>'
            f'<desc id="dg-grid-desc">{escape(desc)}</desc>' + ''.join(text) + left + slice_a + slice_b + '</svg>')


def render(record):
    observations = validate_report(record)
    sources = json.loads((ROOT / 'analysis/q7-dcp-interpolation-sources.json').read_text(encoding='utf-8'))
    probes = observations['probes']
    tables = observations['dcp']['tables']
    assert observations['probe_count'] == len(probes) == 15
    assert len({tuple(p['input_hsv_degrees']) for p in probes}) == 5 and len({p['table'] for p in probes}) == 3
    worst = max(p['decimal_reference_max_abs_error'] for p in probes)
    assert worst == observations['independent_reference_max_abs_error'] == 1.9539925233402755e-14
    assert observations['dcp']['sdk_default_encoding'] == {'name': 'encoding_Linear', 'value': 0}
    assert not any(observations['dcp']['encoding_tags_present'].values())
    assert tables['ProfileLookTableData']['value_scale'] == {'min': 1.0, 'max': 1.0}
    assert tables['ProfileHueSatMapData1']['value_scale']['min'] < 1 < tables['ProfileHueSatMapData1']['value_scale']['max']
    scope = observations['scope']
    assert not (scope['native_SDK_executed'] or scope['RAW_or_Lightroom_rendered'] or scope['firmware_executed']
                or scope['table_node_values_exported'] or scope['whole_LUT_or_matrix_exported'])
    assert observations['sources']['source_files_verified'] == len(sources['sources']) == 8
    assert sources['sdk_zip']['bytes'] == 80509918
    tests = (ROOT / 'tests/test_q7_dcp_interpolation.py').read_text(encoding='utf-8').count('    def test_')

    rows = []
    for p in probes:
        rows.append(f'<tr><th scope="row">{SHORT[p["table"]]}</th><td class="n">{stack(p["input_hsv_degrees"])}</td>'
                    f'<td class="n">{stack(p["weighted_coefficients_degrees_scale_scale"])}</td>'
                    f'<td class="n">{stack(p["derived_output_hsv_degrees"])}</td>'
                    f'<td class="n">{sci(p["decimal_reference_max_abs_error"])}</td></tr>')
    source_rows = []
    for item in sources['sources']:
        spans = ', '.join(f'{s["first_line"]}~{s["last_line"]}' for s in item['spans'])
        source_rows.append(f'<tr><th scope="row"><code>{escape(item["file"])}</code></th><td>{spans}</td>'
                           f'<td class="n">{item["bytes"]:,}</td><td><code class="wrap">{item["sha256"]}</code></td></tr>')
    first = probes[0]
    values = {
        '{{GRID}}': diagram(first['input_hsv_degrees'], tables['ProfileHueSatMapData1']['dimensions_hsv'],
                            tables['ProfileLookTableData']['dimensions_hsv']),
        '{{PROBES}}': ''.join(rows),
        '{{SOURCES}}': ''.join(source_rows),
        '{{MAX_ERROR}}': repr(worst),
        '{{MAX_ERROR_SCI}}': sci(worst),
        '{{TESTS}}': str(tests),
        '{{SDK_ZIP}}': sources['sdk_zip']['sha256'],
        '{{SDK_BYTES}}': f'{sources["sdk_zip"]["bytes"]:,}',
        '{{DCP_SHA}}': observations['dcp']['sha256'],
        '{{RAW_SHA}}': record['_publication']['research_observations_raw_sha256'],
        '{{OBSERVATIONS_SHA}}': canonical(observations),
    }
    text = (ROOT / 'analysis/q7-dcp-interpolation-template.html').read_text(encoding='utf-8')
    for key, value in values.items():
        if text.count(key) != 1:
            raise ValueError('Expected one template marker: ' + key)
        text = text.replace(key, value)
    if '{{' in text:
        raise ValueError('Unexpanded template marker')
    return text


def main():
    text = render(load_record())
    (ROOT / 'reports').mkdir(exist_ok=True)
    (ROOT / 'reports/q7-dcp-interpolation.html').write_text(text, encoding='utf-8', newline='\n')
    print('Built q7-dcp-interpolation.html')


if __name__ == '__main__':
    main()
