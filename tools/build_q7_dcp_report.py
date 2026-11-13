"""Build the DCP structure report (reports/q7-dcp-structure.html) from the frozen record.

Every table, the side-by-side tag diagram and the numbers quoted in the template prose come from
analysis/q7-dcp-structure.json; fixed numbers written in the template are asserted here first.
"""
from html import escape
from pathlib import Path

from check_q7_dcp_structure import load_record, canonical

ROOT = Path(__file__).resolve().parents[1]

ROLE = {"adobe": "Adobe Standard", "matrix": "matrix-test"}
# EXIF LightSource codes used by CalibrationIlluminant (DNG 1.7.1.0, p. 31).
ILLUMINANT = {17: "표준광 A", 21: "D65"}

# Tags grouped by what they do in a profile (DNG 1.7.1.0, chapter 4 and 6).
GROUPS = (
    ("식별·정책", ("UniqueCameraModel", "ProfileName", "ProfileCalibrationSignature", "ProfileCopyright", "ProfileEmbedPolicy")),
    ("광원", ("CalibrationIlluminant1", "CalibrationIlluminant2")),
    ("색 행렬", ("ColorMatrix1", "ColorMatrix2", "ForwardMatrix1", "ForwardMatrix2")),
    ("색 보정 표", ("ProfileHueSatMapDims", "ProfileHueSatMapData1", "ProfileHueSatMapData2", "ProfileLookTableDims", "ProfileLookTableData")),
    ("톤 곡선", ("ProfileToneCurve",)),
)

PRESENCE = ("ColorMatrix1", "ColorMatrix2", "ForwardMatrix1", "ForwardMatrix2", "ProfileHueSatMapDims",
            "ProfileHueSatMapData1", "ProfileHueSatMapData2", "ProfileLookTableDims", "ProfileLookTableData",
            "ProfileToneCurve", "ProfileHueSatMapEncoding", "ProfileLookTableEncoding", "BaselineExposure",
            "BaselineExposureOffset", "DefaultBlackRender")


def fmt(value):
    return f"{value:.6g}"


def interval(s):
    return fmt(s["min"]) + " ~ " + fmt(s["max"])


def table(caption, headers, rows, numeric=(), cls=""):
    """rows: lists of already-escaped cell HTML; the first cell becomes the row header."""
    head = "".join(f'<th scope="col">{escape(h)}</th>' for h in headers)
    body = []
    for row in rows:
        cells = [f'<th scope="row">{row[0]}</th>']
        for i, cell in enumerate(row[1:], 1):
            cells.append(f'<td class="n">{cell}</td>' if i in numeric else f"<td>{cell}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    attr = f' class="{cls}"' if cls else ""
    return (f'<div class="table-wrap"><table{attr}><caption>{escape(caption)}</caption><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def cell_text(profile, tag):
    """Short label for one tag of one profile in the diagram, or None when absent."""
    if tag == "ProfileToneCurve":
        return None if profile["tone_curve"]["status"] == "absent" else "있음"
    entry = next((e for e in profile["directory"] if e["name"] == tag), None)
    if entry is None:
        return None
    if tag in profile.get("tables", {}):
        t = profile["tables"][tag]
        return f'{t["nodes"]:,}노드 · {entry["payload_bytes"]:,}바이트'
    info = profile["tags"][tag]
    if "dimensions" in info:
        return " × ".join(map(str, info["dimensions"]))
    if "text" in info:
        text = info["text"]
        return "“" + text.rstrip(" ") + "␣" * (len(text) - len(text.rstrip(" "))) + "”"
    if "value" in info:
        return f'값 {info["value"]} ({ILLUMINANT[info["value"]]})'
    if tag.startswith(("ColorMatrix", "ForwardMatrix")):
        return f'3×3 · {entry["payload_bytes"]}바이트'
    return f'{entry["payload_bytes"]}바이트'


def diagram(a, m):
    """Side-by-side tag map of the two files, drawn from the directory records."""
    x_label, x_a, x_m, w = 8, 300, 552, 240
    row_h, y = 26, 64
    parts = []
    rows_svg = []
    for group, tags in GROUPS:
        top = y
        y += 22
        for tag in tags:
            rows_svg.append(f'<text class="s mono" x="{x_label + 12}" y="{y + 17}">{tag}</text>')
            for x, p in ((x_a, a), (x_m, m)):
                label = cell_text(p, tag)
                state = "ok" if label else "mute"
                rows_svg.append(f'<rect class="b {state}" x="{x}" y="{y + 2}" width="{w}" height="{row_h - 4}" rx="5"/>')
                rows_svg.append(f'<text class="s" x="{x + 10}" y="{y + 17}">{escape(label or "없음")}</text>')
            y += row_h
        parts.append(f'<rect class="gf" x="0" y="{top}" width="800" height="{y - top + 4}" rx="8"/>'
                     f'<text class="h" x="{x_label + 4}" y="{top + 16}">{group}</text>')
        y += 10
    height = y + 4
    head = (f'<text class="t" x="{x_a}" y="22">{ROLE["adobe"]}</text>'
            f'<text class="s" x="{x_a}" y="42">{a["bytes"]:,}바이트 · 태그 {a["ifd_entry_count"]}개</text>'
            f'<text class="t" x="{x_m}" y="22">{ROLE["matrix"]}</text>'
            f'<text class="s" x="{x_m}" y="42">{m["bytes"]:,}바이트 · 태그 {m["ifd_entry_count"]}개</text>'
            f'<text class="t" x="{x_label + 4}" y="22">태그 (역할별)</text>')
    desc = (f'두 DCP 파일에 저장된 태그를 역할별로 나란히 놓은 그림입니다. 왼쪽 열은 Adobe Standard({a["bytes"]:,}바이트, 태그 {a["ifd_entry_count"]}개), '
            f'오른쪽 열은 matrix-test({m["bytes"]:,}바이트, 태그 {m["ifd_entry_count"]}개)입니다. '
            'Adobe Standard에는 식별 태그 다섯 개, 광원 두 개, ColorMatrix와 ForwardMatrix 각 두 개, HueSatMap 표 두 개와 LookTable 하나가 있습니다. '
            'matrix-test에는 카메라 모델 이름, 프로파일 이름, 광원 두 개, ColorMatrix 두 개만 있고 ForwardMatrix와 표는 없습니다. '
            '두 파일 모두 ProfileToneCurve가 없습니다.')
    return ('<svg class="dg" viewBox="0 0 800 ' + str(height) + '" role="img" aria-labelledby="dg-tags-title dg-tags-desc">'
            '<title id="dg-tags-title">두 DCP 파일의 태그 구성 비교</title>'
            f'<desc id="dg-tags-desc">{escape(desc)}</desc>' + head + "".join(parts) + "".join(rows_svg) + "</svg>")


def check_prose_numbers(d):
    """Numbers written as plain text in the template must match the record."""
    a, m = d["profiles"]["adobe"], d["profiles"]["matrix"]
    assert (a["bytes"], a["ifd_entry_count"], m["bytes"], m["ifd_entry_count"]) == (120686, 16, 270, 6)
    t = a["tables"]
    assert [t[k]["nodes"] for k in ("ProfileHueSatMapData1", "ProfileHueSatMapData2", "ProfileLookTableData")] == [2700, 2700, 4608]
    assert t["ProfileHueSatMapData1"]["dimensions_hsv"] == [90, 30, 1] and t["ProfileLookTableData"]["dimensions_hsv"] == [36, 8, 16]
    assert t["ProfileLookTableData"]["value_scale"] == {"min": 1.0, "max": 1.0}
    assert all(x["zero_saturation_value_all_one"] and x["nonnegative_scales"] for x in t.values())
    assert m["tables"] == {} and "ForwardMatrix1" not in m["tags"]
    for p in (a, m):
        assert p["tone_curve"]["status"] == "absent" and not any(p["optional_presence"].values())
    assert d["adobe_forward_pair_payload_equal"] is True
    assert (a["tags"]["UniqueCameraModel"]["text"], m["tags"]["UniqueCameraModel"]["text"]) == ("PENTAX Q7", "PENTAX Q7 ")
    assert (a["tags"]["CalibrationIlluminant1"]["value"], a["tags"]["CalibrationIlluminant2"]["value"]) == (17, 21)
    k3 = d["k3iii_archived_comparison"]
    assert k3["tone_curve_present"] is False and k3["input_reparsed"] is False
    h = d["historical_as_shot_q7"]
    assert (h["baseline_temperature_tint"], h["profile_temperature_tint"], h["lightroom_version"]) == ([5100, -17], [4900, -7], "16.0")
    assert h["strict_profile_only_passed"] is False
    assert d["parser"]["sha256_lf"] == "83c9ea9d745a4ac12bba4164ff729aeb8e64bdd3783e8575727251758ee3a7e7"
    assert d["_publication"]["k3iii_public_commit"] == "2b50cf4f46a61b077789692b3ccc851d4d8d65b9"
    assert d["self_checks"]["tone_checks"] == 8


def main():
    d = load_record()
    check_prose_numbers(d)
    a, m = d["profiles"]["adobe"], d["profiles"]["matrix"]

    def presence(p, tag):
        v = p["tags"].get(tag)
        if v is None:
            return '<span class="muted">없음</span>'
        if "dimensions" in v:
            return escape(" × ".join(map(str, v["dimensions"])))
        return f'type {v["type"]}, count {v["count"]:,}'

    structural = [[f"<code>{tag}</code>", presence(a, tag), presence(m, tag)] for tag in PRESENCE]
    short = {"ProfileHueSatMapData1": "HueSatMap 1", "ProfileHueSatMapData2": "HueSatMap 2", "ProfileLookTableData": "LookTable"}
    tables = [[short[n], "×".join(map(str, t["dimensions_hsv"])), f'{t["nodes"]:,}',
               interval(t["hue_shift_degrees"]), interval(t["saturation_scale"]), interval(t["value_scale"]),
               f'{t["zero_saturation_nodes"]:,}', f'{t["identity_nodes"]:,}'] for n, t in a["tables"].items()]
    matrix_rows = [[escape(ROLE[k]), f"<code>{n}</code>", interval(v["range"]), fmt(v["determinant"])]
                   for k, p in (("adobe", a), ("matrix", m)) for n, v in p["matrices"].items()]
    diff = d["color_matrix_difference"]
    diff_rows = [[f"<code>{n}</code>", "같음" if v["payload_equal"] else "다름", fmt(v["max_abs_element_difference"])]
                 for n, v in diff.items()]
    inputs = [[escape(ROLE[k]), f'<code>{escape(p["file"])}</code>', f'{p["bytes"]:,}',
               escape(p["tags"]["ProfileName"]["text"]), f'<code class="wrap">{p["sha256"]}</code>'] for k, p in (("adobe", a), ("matrix", m))]
    directory = [[str(r["tag"]), f'<code>{r["name"]}</code>', str(r["type"]), f'{r["count"]:,}', f'{r["entry_offset"]:,}',
                  f'{r["payload_offset"]:,}', f'{r["payload_bytes"]:,}'] for r in a["directory"]]
    k3 = d["k3iii_archived_comparison"]
    h = d["historical_as_shot_q7"]
    values = {
        "{{TAG_DIAGRAM}}": diagram(a, m),
        "{{STRUCTURE}}": table("색 처리에 관여하는 태그의 유무 (없음 = 파일에 저장되지 않음)", ["태그", ROLE["adobe"], ROLE["matrix"]], structural, cls="compact"),
        "{{TABLES}}": table("Adobe Standard에 든 세 표의 값 범위 (전체 노드의 최솟값 ~ 최댓값)",
                            ["표", "H × S × V", "노드 수", "색상 이동(°)", "채도 배율", "명도 배율", "S=0 노드", "변화 없는 노드"],
                            tables, numeric=(2, 6, 7), cls="compact"),
        "{{MATRICES}}": table("저장된 행렬 원소의 범위와 행렬식", ["파일", "행렬", "원소 범위", "행렬식"], matrix_rows, numeric=(3,), cls="fit"),
        "{{CM_DIFF}}": table("두 파일의 ColorMatrix 원소 비교", ["행렬", "저장 바이트", "원소 차이의 최댓값"], diff_rows, numeric=(2,), cls="fit"),
        "{{INPUTS}}": table("분석에 쓴 두 DCP 파일", ["역할", "파일 이름", "바이트", "ProfileName", "SHA-256"], inputs, numeric=(2,), cls="compact"),
        "{{DIRECTORY}}": table("Adobe Standard의 IFD 엔트리 16개 (오프셋은 파일 시작 기준 바이트)",
                               ["태그 번호", "이름", "type", "count", "엔트리 위치", "값 위치", "값 바이트"], directory,
                               numeric=(3, 4, 5, 6), cls="compact"),
        "{{K3_SAME}}": ", ".join(f"<code>{x}</code>" for x in k3["matching_shared_payloads"]),
        "{{K3_DIFF}}": ", ".join(f"<code>{x}</code>" for x in k3["differing_shared_payloads"]),
        "{{SUMMARY_SHA}}": canonical(d),
    }
    text = (ROOT / "analysis/q7-dcp-template.html").read_text(encoding="utf-8")
    for key, value in values.items():
        if text.count(key) != 1:
            raise ValueError("Expected one template marker: " + key)
        text = text.replace(key, value)
    if "{{" in text:
        raise ValueError("Unexpanded template marker")
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports/q7-dcp-structure.html").write_text(text, encoding="utf-8", newline="\n")
    print("Built q7-dcp-structure.html")


if __name__ == "__main__":
    main()
