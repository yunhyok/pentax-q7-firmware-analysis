"""Build reports/color-engine-tables.html from analysis/color-engine-tables.json."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GROUP_LABELS = (
    ('matrices_s16', '단일 색 행렬 (signed 16-bit)', 'CameraBasic, MakeUp, SatCtl, FilterEffect, HueShift, sRGB→AdobeRGB'),
    ('matrix_sets_6_s16', '6구역 색 행렬 묶음', 'Custom Image 11종의 색상 6분할 행렬 (v1.01에서는 6개 모두 동일)'),
    ('tone_u16', '톤·리버설 곡선 (256점 unsigned 16-bit)', 'BasicTone 15개 + ReversalTone 7개 (포화점 16130)'),
    ('dng_color_matrix_s32_pairs', 'DNG ColorMatrix 분수 쌍', 'arcnlDNGColorMatrix1(A광), arcnlDNGColorMatrix2(D65, 분모 65536)'),
    ('ycbcr_s16', 'YCbCr 변환 행렬', 'arcnwYCbCrConversionMatrixDefault (1.0 = 256)'),
    ('chroma_offsets_s16', '조색 Cb·Cr 오프셋', 'cnarsCb/CrAddition (+AdobeRGB), cnarsCb/CrOffset (+AdobeRGB)'),
    ('tone_constants_u16', '톤 포화 상수', 'cnwBasicToneSaturationPointMin(16130), Output(4095), BaseNumber(64)'),
    ('composition_rate_u16', '하이라이트·섀도 합성 비율 (97점)', 'cnwHighlightShadowCompositionRate2048 (1.0 = 2048)'),
    ('custom_image_records_u8', 'Custom Image · 장면 기본값 (28바이트)', 'cntCustomImageUnit* 23개 레코드'),
    ('chroma_suppression_u16', '암부 채도 억제 LUT (2048점)', 'arwCChromaSuppressionRatioLut (1.0 = 8192, 최하 0.5)'),
    ('chroma_suppression_param_u16', '하이라이트 채도 억제 파라미터', 'arcntChromaSuppression (시작 밝기 200 등 17워드)'),
    ('anonymous', '미명명 정적 표 4종', '키 표 9개, 리버설 경계 7개, CM 기본 행렬, 3D LUT 격자 9개'),
)

UNIT_MODES = (
    ('Natural', 'Natural'),
    ('Vivid', 'Bright (Vivid)'),
    ('Portrait', 'Portrait'),
    ('Landscape', 'Landscape'),
    ('Miyabi', 'Vibrant (Miyabi)'),
    ('Gokusai', 'Radiant (Gokusai)'),
    ('Honoka', 'Muted (Honoka)'),
    ('BleachBypass', 'Bleach Bypass'),
    ('Reversal', 'Reversal Film'),
    ('CrossProcess', 'Cross Processing'),
    ('Monotone', 'Monochrome (Monotone)'),
)


def _pipeline_svg() -> str:
    return ''.join([
        '<svg class="dg" viewBox="0 0 800 220" role="img" aria-labelledby="dg-q7c-title dg-q7c-desc">',
        '<title id="dg-q7c-title">Q7 Custom Image 색 처리 계산 구조</title>',
        '<desc id="dg-q7c-desc">MakeColorMatrix가 6구역 색 행렬과 FC1 계수를 만들고, CalcGammaCorrectionTable이 표 A를, CalcBasicGammaCorrectionTable이 표 D를 만듭니다. MakeColorReproductionLutParam은 표 D의 격자 입력에 6행렬과 암부 채도 억제와 표 A를 순서대로 적용해 9x9x9 3차원 표를 출력합니다.</desc>',
        '<defs><marker id="dg-q7c-ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path class="ah" d="M0 0L10 5L0 10z"/></marker></defs>',
        '<rect class="b ok" x="10" y="20" width="180" height="58" rx="8"/>',
        '<text class="t" x="22" y="44">MakeColorMatrix</text>',
        '<text class="s" x="22" y="64">6구역 색 행렬 · FC1 · 조색</text>',
        '<rect class="b ok" x="10" y="92" width="180" height="54" rx="8"/>',
        '<text class="t" x="22" y="116">CalcGammaCorrection</text>',
        '<text class="s" x="22" y="136">표 A (일반 또는 Reversal)</text>',
        '<rect class="b ok" x="10" y="158" width="180" height="52" rx="8"/>',
        '<text class="t" x="22" y="180">CalcBasicGamma</text>',
        '<text class="s" x="22" y="200">표 D (하드웨어 감마)</text>',
        '<rect class="b key" x="240" y="68" width="248" height="86" rx="8"/>',
        '<text class="t" x="254" y="96">MakeColorReproductionLutParam</text>',
        '<text class="s" x="254" y="118">표 D 격자 → 6행렬 → YCbCr → 암부억제 → 표 A</text>',
        '<text class="s" x="254" y="138">9×9×9 = 729 RGB 격자 출력</text>',
        '<rect class="b model" x="538" y="68" width="250" height="86" rx="8"/>',
        '<text class="t" x="552" y="96">사면체 보간 + 하이라이트 억제</text>',
        '<text class="s" x="552" y="118">FC1(색상 회전·조색) · 채도 억제(≥200)</text>',
        '<text class="s" x="552" y="138">카메라 JPEG 10종 ΔE76 0.97~1.43</text>',
        '<path class="e" d="M190 49H215V95H238" marker-end="url(#dg-q7c-ah)"/>',
        '<path class="e" d="M190 119H238" marker-end="url(#dg-q7c-ah)"/>',
        '<path class="e" d="M190 184H215V130H238" marker-end="url(#dg-q7c-ah)"/>',
        '<path class="e" d="M488 111H536" marker-end="url(#dg-q7c-ah)"/>',
        '</svg>',
    ])


def render(tables: dict) -> str:
    counts = {k: len(v) for k, v in tables.items() if k not in ('firmware', 'scope')}
    total = sum(counts.values())
    group_rows = []
    for key, label, desc in GROUP_LABELS:
        if key not in counts:
            raise ValueError(f'Missing group {key} in color-engine-tables.json')
        group_rows.append(
            f'<tr><th scope="row">{label}<br><code class="small muted">{escape(key)}</code></th>'
            f'<td class="n"><strong>{counts[key]}</strong></td><td>{escape(desc)}</td></tr>'
        )

    cam_basic = tables['matrices_s16']['cnsCameraBasicMatrix']
    comp = tables['composition_rate_u16']['cnwHighlightShadowCompositionRate2048']
    unit_records = tables['custom_image_records_u8']
    unit_rows = []
    for suffix, label in UNIT_MODES:
        vals = unit_records[f'cntCustomImageUnit{suffix}']['values']
        signed = [v - 4 for v in vals[1:6]]  # sat, contrast, sharp, key, hue
        toning = vals[8]
        unit_rows.append(
            f'<tr><th scope="row">{escape(label)}</th><td class="n">{vals[0]}</td>'
            f'<td class="n">{signed[0]:+d}</td><td class="n">{signed[1]:+d}</td>'
            f'<td class="n">{signed[2]:+d}</td><td class="n">{signed[3]:+d}</td>'
            f'<td class="n">{signed[4]:+d}</td><td class="n">{toning}</td></tr>'
        )

    values = {
        '{{TOTAL_TABLES}}': str(total),
        '{{GROUP_ROWS}}': ''.join(group_rows),
        '{{CAM_BASIC_ADDR}}': cam_basic['address'],
        '{{CAM_BASIC_VALUES}}': ' '.join(str(x) for x in cam_basic['values']),
        '{{COMP_ADDR}}': comp['address'],
        '{{PIPELINE_SVG}}': _pipeline_svg(),
        '{{UNIT_ROWS}}': ''.join(unit_rows),
    }
    text = (ROOT / 'analysis/color-engine-template.html').read_text(encoding='utf-8')
    for k, v in values.items():
        if k not in text:
            raise ValueError(f'Missing marker {k}')
        text = text.replace(k, v)
    if '{{' in text:
        raise ValueError('Unexpanded marker in color-engine-template.html')
    return text


def main() -> int:
    tables = json.loads((ROOT / 'analysis/color-engine-tables.json').read_text(encoding='utf-8'))
    html = render(tables)
    (ROOT / 'reports').mkdir(exist_ok=True)
    (ROOT / 'reports/color-engine-tables.html').write_text(html, encoding='utf-8', newline='\n')
    print('Built reports/color-engine-tables.html')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
