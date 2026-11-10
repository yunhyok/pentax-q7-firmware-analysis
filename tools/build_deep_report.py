"""Render the follow-up HTML from reviewed copy and measured evidence."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
def read(name):
    return json.loads((ROOT / "analysis" / name).read_text(encoding="utf-8"))
def esc(value):
    return html.escape(str(value))


def _text_width(text, size, mono=False):
    """Rough rendered width: full-width for CJK, about half an em for Latin."""
    return sum(size if ord(ch) > 0x2E7F else size * (0.61 if mono else 0.57) for ch in text)


def _fit(text, size, room, mono=False):
    """Squeeze a label that would overflow its node instead of letting it spill out."""
    return f' textLength="{room}" lengthAdjust="spacingAndGlyphs"' if _text_width(text, size, mono) > room else ""


def diagram(key, title, nodes, edges, height, caption):
    """Three-column node grid drawn with the shared .dg diagram classes (assets/site.css).

    Node positions keep the historical 1000-unit grid (x = 20, 350, 700) and are scaled to the
    800-unit canvas used by every diagram on the site.
    """
    width, tall, room = 232, 60, 208
    def place(node):
        x, y, *_ = node
        return round(8 + (x - 20) * 0.8), round(y * 0.8) + 4
    parts = [f'<figure class="diagram"><figcaption>{esc(title)}</figcaption><div class="dg-scroll">'
             f'<svg class="dg" viewBox="0 0 800 {round(height * 0.8) + 8}" role="img" aria-labelledby="{key}-title {key}-desc">'
             f'<title id="{key}-title">{esc(title)}</title><desc id="{key}-desc">{esc(caption)}</desc>'
             f'<defs><marker id="{key}-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
             f'<path class="ah" d="M0 0L10 5L0 10z"/></marker></defs>']
    for source, target, dashed in edges:
        x, y = place(nodes[source])
        tx, ty = place(nodes[target])
        if x == tx:
            path = f"M{x + width // 2} {y + tall}V{ty}" if ty > y else f"M{x + width // 2} {y}V{ty + tall}"
        elif tx < x:
            path = f"M{x} {y + tall // 2}H{tx + width}" if ty == y else f"M{x} {y + tall // 2}H{x - 14}V{ty + tall // 2}H{tx + width}"
        else:
            path = f"M{x + width} {y + tall // 2}H{tx}" if ty == y else f"M{x + width} {y + tall // 2}H{tx - 14}V{ty + tall // 2}H{tx}"
        parts.append(f'<path class="e{" dash" if dashed else ""}" d="{path}" marker-end="url(#{key}-arrow)"/>')
    for node in nodes.values():
        x, y = place(node)
        label, subtitle = str(node[2]), str(node[3])
        parts.append(f'<rect class="b" x="{x}" y="{y}" width="{width}" height="{tall}" rx="8"/>'
                     f'<text class="t" x="{x + 12}" y="{y + 25}"{_fit(label, 14.5, room)}>{esc(label)}</text>'
                     f'<text class="s mono" x="{x + 12}" y="{y + 45}"{_fit(subtitle, 12, room, True)}>{esc(subtitle)}</text>')
    return "".join(parts) + f'</svg></div><p>{esc(caption)} <a href="analysis/deep-evidence.json">[S3]</a></p></figure>'


# Later reports that refine a row of the K-3 Mark III comparison (row number -> link).
_LATER = {
    2: ('routing-report.html', '수신자 확인: 렌즈 명령·ISP 레지스터'),
    5: ('af-completion-report.html', '큐·완료 조건: AF 명령과 완료'),
    9: ('pixel-report.html', 'HDR 주 이미지 압축 위치: HDR 버퍼'),
    12: ('recompiled-numeric-report.html', 'C 재컴파일: 색 행렬 함수'),
    14: ('routing-report.html', '통계용 감마 LUT 포트'),
    17: ('routing-report.html', '센서 이득 설정까지(연결은 미확인)'),
    18: ('routing-report.html', 'CM·FC1 레지스터 경로'),
}
_KINDS = {'call': '직접 호출', 'jump': '직접 점프', 'indirect-call': '간접 호출', 'indirect-jump': '간접 점프'}


def _jpeg_figure():
    """The JPEG submit/completion grid, with the shared legend and a plain evidence link."""
    figure = diagram("jpg", "JPEG 경로 제출(위)과 완료 인터럽트(아래)", {
        "a": (20, 10, "ApsCmpGetCodeSizeBySf", "PathCreate(1) / 0x8014b790"),
        "p": (350, 10, "PathSubmit", "0x801c83c8 / type == 1"),
        "j": (700, 10, "JpegPathSubmit", "bit 0x40 -> IcaPathSubmit"),
        "i": (20, 170, "JpegPathInit", "ISR 등록 / ID 0x14"),
        "d": (350, 170, "IsrJpegDone", "상태 읽기 0xb0181ca0"),
        "e": (700, 170, "이벤트 비트 설정", "0이면 0x04 / 아니면 0x40")},
        [("a", "p", False), ("p", "j", False), ("i", "d", True), ("d", "e", False)], 270,
        "위쪽 실선은 코드 크기 계산에서 시작하는 경로 제출의 직접 호출입니다. 아래쪽 점선은 인터럽트 처리 함수를 "
        "등록하는 관계이며 실행 순서를 뜻하지 않습니다. 양자화 테이블이 하드웨어 레지스터에 들어가는 지점은 그리지 않았습니다.")
    figure = figure.replace('<a href="analysis/deep-evidence.json">[S3]</a>',
                            '<a href="analysis/deep-evidence.json">[근거: deep-evidence.json]</a>')
    legend = ('<ul class="dg-legend"><li><i class="static"></i>실선: 명령어에서 읽은 직접 호출</li>'
              '<li><i class="open"></i>점선: 등록 관계(호출 아님)</li></ul>')
    return figure.replace('</figure>', legend + '</figure>')


def main():
    values = {}
    decoded = read("segment-decode.json")
    segments = decoded["segments"]
    values["segments"] = "".join(
        f'<tr><th scope="row">{esc(s["name"])}</th><td><code>{s["file_offset"]:#x}–{s["file_end"]:#x}</code></td>'
        f'<td><code>{s["virtual_address"]:#x}–{s["virtual_address"] + s["decoded_size"]:#x}</code></td>'
        f'<td class="n">{s["decoded_size"]:,}</td><td class="n">{s["block_count"]}</td></tr>' for s in segments)
    values["decoded_total"] = f'{sum(s["decoded_size"] for s in segments):,}'
    values["block_total"] = str(sum(s["block_count"] for s in segments))
    values["segment_hashes"] = "".join(
        f'<tr><th scope="row">{esc(s["name"])}</th><td><code class="wrap">{s["compressed_sha256"]}</code></td>'
        f'<td><code class="wrap">{s["decoded_sha256"]}</code></td></tr>' for s in segments)
    values["decode_evidence"] = "".join(
        f'<tr><td><code>{esc(e["virtual_address"])}</code></td><td><code>{esc(e["file_offset"])}</code></td>'
        f'<td lang="en">{esc(e["observation"])}</td></tr>' for e in decoded["firmware_evidence"])
    symbols = read("main-symbols.json")
    for key in ("symbol_records", "unique_addresses", "unique_names"):
        values[key] = f"{symbols[key]:,}"
    values["symbol_sources"] = "".join(
        f'<tr><th scope="row"><code>{esc(s["name"])}</code></th><td class="n">{s["size"]:,}</td>'
        f'<td><code>{s["file_spans"][0]["offset"]:#x}</code></td><td><code class="wrap">{s["sha256"]}</code></td></tr>'
        for s in symbols["sources"])
    geometry = symbols["geometry"]
    values["volume_offset"] = f'{geometry["volume_offset"]:#x}'
    values["declared_volume"] = f'{geometry["declared_volume_bytes"]:,}'
    values["input_size"] = f'{decoded["input_size"]:,}'

    evidence = read("deep-evidence.json")
    decompilation = read("decompilation.json")
    warnings = {f["address"]: len(f["warnings"]) for f in decompilation["functions"]}
    functions = sorted(evidence["functions"], key=lambda f: f["address"])
    values["function_count"] = str(len(functions))
    values["e03_count"] = str(sum(1 for f in functions if f.get("segment", "E03 plain") == "E03 plain"))
    values["e04_count"] = str(sum(1 for f in functions if f.get("segment") == "E04"))
    values["warned_count"] = str(sum(1 for n in warnings.values() if n))
    values["indirect_warned"] = ", ".join(f"<code>{esc(n)}</code>" for n in decompilation["functions_with_unrecovered_indirect_warnings"])
    kinds = {}
    for f in functions:
        for t in f["transfers"]:
            kinds[t["kind"]] = kinds.get(t["kind"], 0) + 1
    values["transfer_total"] = f"{sum(kinds.values()):,}"
    values["transfer_kinds"] = "".join(
        f'<tr><th scope="row">{_KINDS[k]}</th><td class="n">{kinds.get(k, 0):,}</td></tr>' for k in _KINDS)
    values["ghidra"] = esc(decompilation["tool"])
    values["java"] = esc(decompilation["java"])
    values["analysis_elf_sha256"] = decompilation["analysis_elf_sha256"]
    values["function_rows"] = "".join(
        f'<tr id="fn-{f["address"]:08x}"><th scope="row">{esc(f["name"])}</th><td><code>0x{f["address"]:08x}</code></td>'
        f'<td class="n">{f["size"]:,}</td><td class="n">{len(f["transfers"])}</td>'
        f'<td class="n">{warnings[f["address"]]}</td><td>{esc(f.get("segment", "E03 plain"))}</td></tr>'
        for f in functions)

    math = read("color-math-checks.json")
    names = {0x8041BC90: "MatrixMultiplication", 0x8041BE94: "HueShift"}
    values["math_engine"] = esc(math["engine"])
    values["math_count"] = str(len(math["cases"]))
    values["math_passed"] = str(sum(1 for c in math["cases"] if c["passed"]))
    cases = {"identity": "단위 행렬 × 계수 행렬", "signed": "음수 계수 × 무작위 행렬", "alias-left": "출력이 왼쪽 입력과 같은 주소"}
    values["math_rows"] = "".join(
        f'<tr><th scope="row">{names[c["address"]]}</th><td>{cases.get(c["case"], esc(c["case"]))}</td>'
        f'<td class="n">{c["shift"]}</td><td><code class="wrap">{", ".join(map(str, c["actual"]))}</code></td>'
        f'<td>{"일치" if c["passed"] and c["actual"] == c["expected"] else "불일치"}</td></tr>' for c in math["cases"])

    comparison = read("comparison.json")
    values["k3_commit"] = comparison["k3_commit"]
    rows = []
    for i, (name, path, status, detail) in enumerate(comparison["rows"], 1):
        later = _LATER.get(i)
        cell = f'<a href="{later[0]}">{esc(later[1])}</a>' if later else "—"
        rows.append(f'<tr><th scope="row"><a href="{comparison["k3_repository"]}/blob/{comparison["k3_commit"]}/analysis/{path}">'
                    f'{i}. {esc(name)}</a></th><td>{esc(status)}</td><td>{esc(detail)}</td><td>{cell}</td></tr>')
    values["comparison_rows"] = "".join(rows)
    values["comparison_count"] = str(len(comparison["rows"]))
    values["jpeg_diagram"] = _jpeg_figure()

    page = (ROOT / "analysis/deep-template.html").read_text(encoding="utf-8")
    for key, value in values.items():
        page = page.replace("{{" + key + "}}", value)
    assert "{{" not in page, "unresolved template field"
    (ROOT / "deep-report.html").write_text(page, encoding="utf-8", newline="\n")
    print("Built deep-report.html")


if __name__ == "__main__":
    main()
