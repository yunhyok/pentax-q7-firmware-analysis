"""Render static HTML and figures from the committed evidence; no network or dependencies."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    evidence = json.loads((ROOT / "analysis/evidence.json").read_text(encoding="utf-8"))
    copy = json.loads((ROOT / "analysis/report-copy.json").read_text(encoding="utf-8"))
    template = (ROOT / "analysis/report-template.html").read_text(encoding="utf-8")
    escape = html.escape
    rows, bars = [], []
    for n, elf in enumerate(evidence["elfs"], 1):
        kind = "EXEC" if elf["elf_type"] == 2 else "REL"
        start, end = elf["offset"], elf["referenced_end"]
        rows.append(f'<tr><th scope="row">E{n:02}</th><td><code>0x{start:08X}</code></td>'
                    f'<td><code>0x{end:08X}</code></td><td>{kind}</td>'
                    f'<td><code>0x{elf["entry"]:08X}</code></td><td>{elf["symbol_count"]:,}</td>'
                    f'<td>{elf["defined_function_symbol_count"]:,}</td></tr>')
        left, width = start / evidence["input_size"] * 100, (end - start) / evidence["input_size"] * 100
        bars.append(f'<div class="map-row"><span>E{n:02} · {kind}</span><div class="track">'
                    f'<span class="bar {kind.lower()}" style="margin-left:{left:.6f}%;width:{width:.6f}%"></span>'
                    f'</div></div>')
    points = ' '.join(f'{w["offset"]/evidence["input_size"]*1000:.2f},{180-w["entropy"]/8*180:.2f}'
                      for w in evidence["entropy_windows"])
    curve = ('<svg class="entropy" viewBox="0 0 1000 180" preserveAspectRatio="none" role="img" '
             'aria-labelledby="entropy-title entropy-desc"><title id="entropy-title">원본 파일의 엔트로피</title>'
             '<desc id="entropy-desc">가로축은 파일 오프셋 0부터 18,743,520바이트, 세로축은 0부터 8비트/바이트입니다. '
             '정확한 값은 evidence.json의 entropy_windows에 있습니다.</desc>'
             '<path class="grid" d="M0 0H1000 M0 90H1000 M0 180H1000"/>'
             f'<polyline class="curve" points="{points}"/></svg>')
    symbols = []
    for symbol in evidence["elfs"][0]["selected_symbols"]:
        symbols.append(f'<tr><th scope="row"><code>{escape(symbol["name"])}</code></th>'
                       f'<td><code>0x{symbol["value"]:08X}</code></td><td>{symbol["size"]}</td></tr>')
    values = {**{f"copy_{k}": escape(v) for k, v in copy.items()},
              "elf_rows": "\n".join(rows), "elf_map": "\n".join(bars),
              "entropy": curve, "symbols": "\n".join(symbols),
              "sha256": evidence["input_sha256"],
              "last_window_size": str(evidence["entropy_windows"][-1]["size"])}
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    if "{{" in template:
        raise ValueError("unresolved template field")
    (ROOT / "index.html").write_text(template, encoding="utf-8")
    print("index.html rendered from evidence and reviewed Korean prose")


if __name__ == "__main__":
    main()
