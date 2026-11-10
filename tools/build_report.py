"""Render the landing page and the file-structure report from the committed evidence.

Outputs index.html (from analysis/report-template.html) and structure-report.html
(from analysis/structure-template.html). No network access, standard library only.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEFT, WIDTH = 8, 784  # drawing area of an 800-unit wide diagram


def read(name):
    return json.loads((ROOT / "analysis" / name).read_text(encoding="utf-8"))


def kind(elf):
    return "EXEC" if elf["elf_type"] == 2 else "REL"


def file_bar(evidence):
    """One to-scale bar of the whole file: where the twelve ELFs sit."""
    size = evidence["input_size"]

    def x(offset):
        return LEFT + offset / size * WIDTH

    elfs = evidence["elfs"]
    main_start, main_end = elfs[2]["offset"], elfs[5]["referenced_end"]          # E03..E06
    small_start, small_end = elfs[6]["offset"], elfs[10]["referenced_end"]       # E07..E11
    last = elfs[11]                                                               # E12
    parts = [
        '<svg class="dg" viewBox="0 0 800 214" role="img" aria-labelledby="dg-file-title dg-file-desc">',
        '<title id="dg-file-title">Q7 펌웨어 파일 안에서 ELF 12개가 차지하는 위치</title>',
        f'<desc id="dg-file-desc">{size:,}바이트인 파일 전체를 가로 막대 하나로 나타냈습니다. 맨 앞에 업데이트 로더 E01이 있고, '
        '이어서 카메라 본 프로그램인 E03부터 E06이 파일의 약 3분의 1을 차지합니다. 그 뒤에 작은 프로그램 E07부터 E11이 있고, '
        'ELF가 가리키지 않는 넓은 영역을 지나 E12가 있습니다.</desc>',
        f'<rect class="b mute" x="{LEFT}" y="70" width="{WIDTH}" height="70"/>',
    ]
    spans = [(elf["offset"], elf["referenced_end"], "b") for number, elf in enumerate(elfs, 1) if not 3 <= number <= 6]
    spans.append((main_start, main_end, "b key"))  # E03..E06 are contiguous: draw them as one block
    for begin, finish, style in spans:
        start, end = x(begin), x(finish)
        parts.append(f'<rect class="{style}" x="{start:.1f}" y="70" width="{max(end - start, 1):.1f}" height="70"/>')
    middle = (x(main_start) + x(main_end)) / 2
    gap_middle = (x(small_end) + x(last["offset"])) / 2
    last_middle = (x(last["offset"]) + x(last["referenced_end"])) / 2
    small_middle = (x(small_start) + x(small_end)) / 2
    parts += [
        f'<text class="t mid" x="{middle:.1f}" y="100">E03–E06 · 카메라 본 프로그램</text>',
        f'<text class="s mid" x="{middle:.1f}" y="121">E04–E06은 압축되어 있음</text>',
        f'<text class="t mid" x="{gap_middle:.1f}" y="100">ELF 밖 영역</text>',
        f'<text class="s mid" x="{gap_middle:.1f}" y="121">글꼴 같은 자원 (FAT16 구조)</text>',
        f'<text class="t mid" x="{last_middle:.1f}" y="100">E12</text>',
        f'<text class="s mid" x="{last_middle:.1f}" y="121">재배치형</text>',
        f'<path class="e" d="M{x(elfs[0]["offset"]) + 12:.1f} 70V46"/>',
        f'<text class="n" x="{LEFT}" y="36">E01 · 업데이트 로더 (ThreadX·FileX 심볼이 남아 있음)</text>',
        f'<path class="e" d="M{small_middle:.1f} 140V166"/>',
        f'<text class="n mid" x="{small_middle:.1f}" y="182">E07–E11 · 작은 프로그램 5개</text>',
        f'<text class="n" x="{LEFT}" y="206">0</text>',
        f'<text class="n end" x="{LEFT + WIDTH}" y="206">{size:,}바이트</text>',
        '</svg>',
    ]
    return "".join(parts)


def elf_map(evidence):
    """Twelve rows, one per ELF, each drawn to scale against the whole file."""
    size, row, top = evidence["input_size"], 24, 30
    track_left, track_width = 118, 674
    height = top + row * len(evidence["elfs"]) + 26
    parts = [
        f'<svg class="dg" viewBox="0 0 800 {height}" role="img" aria-labelledby="dg-elfmap-title dg-elfmap-desc">',
        '<title id="dg-elfmap-title">ELF 12개가 가리키는 파일 구간</title>',
        '<desc id="dg-elfmap-desc">ELF마다 한 줄씩, 파일 전체 길이에 비례한 위치와 길이로 구간을 그렸습니다. '
        '정확한 시작과 끝은 아래 표에 있습니다.</desc>',
        f'<text class="n" x="{track_left}" y="18">0</text>',
        f'<text class="n end" x="{track_left + track_width}" y="18">{size:,}바이트</text>',
    ]
    for number, elf in enumerate(evidence["elfs"], 1):
        y = top + row * (number - 1)
        start = track_left + elf["offset"] / size * track_width
        length = max((elf["referenced_end"] - elf["offset"]) / size * track_width, 1.5)
        style = "b key" if kind(elf) == "EXEC" else "b static"
        parts.append(
            f'<text class="s" x="8" y="{y + 15}">E{number:02} · {kind(elf)}</text>'
            f'<rect class="b mute" x="{track_left}" y="{y + 4}" width="{track_width}" height="14"/>'
            f'<rect class="{style}" x="{start:.2f}" y="{y + 4}" width="{length:.2f}" height="14"/>'
        )
    parts.append("</svg>")
    return "".join(parts)


def entropy_curve(evidence):
    size = evidence["input_size"]
    left, right, top, bottom = 44, 792, 14, 174
    points = " ".join(
        f'{left + w["offset"] / size * (right - left):.2f},{bottom - w["entropy"] / 8 * (bottom - top):.2f}'
        for w in evidence["entropy_windows"]
    )
    middle = (top + bottom) / 2
    return (
        '<svg class="dg" viewBox="0 0 800 204" role="img" aria-labelledby="dg-entropy-title dg-entropy-desc">'
        '<title id="dg-entropy-title">원본 파일의 엔트로피 분포</title>'
        f'<desc id="dg-entropy-desc">가로축은 파일 오프셋 0부터 {size:,}바이트, 세로축은 0부터 8비트/바이트입니다. '
        '정확한 값은 evidence.json의 entropy_windows에 있습니다.</desc>'
        f'<path class="g" d="M{left} {top}H{right}M{left} {middle}H{right}M{left} {bottom}H{right}"/>'
        f'<text class="n end" x="{left - 6}" y="{top + 4}">8</text>'
        f'<text class="n end" x="{left - 6}" y="{middle + 4}">4</text>'
        f'<text class="n end" x="{left - 6}" y="{bottom + 4}">0</text>'
        f'<polyline class="e key" points="{points}"/>'
        f'<text class="n" x="{left}" y="196">0</text>'
        f'<text class="n mid" x="{(left + right) / 2}" y="196">파일 오프셋</text>'
        f'<text class="n end" x="{right}" y="196">{size:,}바이트</text>'
        '</svg>'
    )


def values():
    evidence, provenance = read("evidence.json"), read("provenance.json")
    segments = read("segment-decode.json")["segments"]
    escape = html.escape
    rows = []
    for number, elf in enumerate(evidence["elfs"], 1):
        rows.append(
            f'<tr><th scope="row">E{number:02}</th><td><code>0x{elf["offset"]:08X}</code></td>'
            f'<td><code>0x{elf["referenced_end"]:08X}</code></td><td>{kind(elf)}</td>'
            f'<td><code>0x{elf["entry"]:08X}</code></td><td class="n">{elf["symbol_count"]:,}</td>'
            f'<td class="n">{elf["defined_function_symbol_count"]:,}</td></tr>'
        )
    symbols = "".join(
        f'<tr><th scope="row"><code>{escape(symbol["name"])}</code></th>'
        f'<td><code>0x{symbol["value"]:08X}</code></td><td class="n">{symbol["size"]}</td></tr>'
        for symbol in evidence["elfs"][0]["selected_symbols"]
    )
    return {
        "elf_rows": "\n".join(rows),
        "elf_map": elf_map(evidence),
        "file_bar": file_bar(evidence),
        "entropy": entropy_curve(evidence),
        "symbols": symbols,
        "sha256": evidence["input_sha256"],
        "input_size": f'{evidence["input_size"]:,}',
        "elf_count": str(evidence["accepted_elf_count"]),
        "elf_magic_count": str(evidence["elf_magic_count"]),
        "symbol_total": f'{sum(e["symbol_count"] for e in evidence["elfs"]):,}',
        "function_symbol_total": f'{sum(e["defined_function_symbol_count"] for e in evidence["elfs"]):,}',
        "block_total": str(sum(s["block_count"] for s in segments)),
        "decoded_total": f'{sum(s["decoded_size"] for s in segments):,}',
        "release_date": provenance["official_release_date"],
        "last_window_size": str(evidence["entropy_windows"][-1]["size"]),
    }


def render(template, output, fields):
    page = (ROOT / "analysis" / template).read_text(encoding="utf-8")
    for key, value in fields.items():
        page = page.replace("{{" + key + "}}", value)
    if "{{" in page:
        raise ValueError(f"unresolved template field in {template}")
    (ROOT / output).write_text(page, encoding="utf-8", newline="\n")
    print(f"Built {output}")


def build_structure():
    render("structure-template.html", "structure-report.html", values())


def main():
    render("report-template.html", "index.html", values())


if __name__ == "__main__":
    main()
    build_structure()
