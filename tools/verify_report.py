"""Check published metadata, deterministic HTML, links and optional original firmware."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urlparse, unquote

from inspect_q7 import inspect
from build_report import main as build
from build_deep_report import main as build_deep
from check_color_math import reference
from build_routing_report import main as build_routing
from verify_routing import verify as verify_routing

ROOT = Path(__file__).resolve().parents[1]


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.ids = [], []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        for field in ("href", "src"):
            if field in attrs:
                self.links.append(attrs[field])
        if tag == "img":
            assert attrs.get("alt"), "image lacks alternative text"
        if tag == "svg" and attrs.get("role") == "img":
            assert attrs.get("aria-labelledby"), "diagram lacks accessible title"


def verify_html(page, builder):
    before = page.read_bytes()
    builder()
    assert page.read_bytes() == before, f"committed {page.name} differs from generated report"
    html = before.decode("utf-8")
    links = Links()
    links.feed(html)
    assert len(links.ids) == len(set(links.ids)), "duplicate HTML ID"
    for link in links.links:
        url = urlparse(link)
        if url.scheme or url.netloc:
            assert url.scheme == "https", f"unexpected external scheme: {link}"
            continue
        path = unquote(url.path)
        assert ".private" not in path and "_workspace" not in path
        if path:
            target = (ROOT / path).resolve()
            assert target.is_relative_to(ROOT) and target.is_file(), f"broken local link: {link}"
            if url.fragment and target.suffix == ".html":
                other = Links()
                other.feed(target.read_text(encoding="utf-8"))
                assert url.fragment in other.ids, f"broken page anchor: {link}"
        elif url.fragment:
            assert url.fragment in links.ids, f"broken anchor: {link}"
    assert "{{" not in html and "C:\\Users" not in html


def read(name):
    return json.loads((ROOT / "analysis" / name).read_text(encoding="utf-8"))


def verify_deep(firmware):
    symbols, decoded, deep, decomp, math = (read(n) for n in
        ("main-symbols.json", "segment-decode.json", "deep-evidence.json", "decompilation.json", "color-math-checks.json"))
    expected_hash = read("provenance.json")["supplied_sha256"]
    assert symbols["input_sha256"] == decoded["input_sha256"] == deep["input_sha256"] == expected_hash
    assert symbols["symbol_records"] == 122154
    assert symbols["unique_addresses"] <= symbols["symbol_records"]
    assert sum(s["block_count"] for s in decoded["segments"]) == 448
    assert sum(s["decoded_size"] for s in decoded["segments"]) == 11266048
    for segment in decoded["segments"]:
        file_cursor, va_cursor = segment["file_offset"], segment["virtual_address"]
        assert len(segment["blocks"]) == segment["block_count"]
        for block in segment["blocks"]:
            assert block["file_offset"] == file_cursor and block["virtual_address"] == va_cursor
            assert file_cursor < block["file_end"] and va_cursor < block["virtual_end"]
            file_cursor, va_cursor = block["file_end"], block["virtual_end"]
        assert file_cursor == segment["file_end"]
        assert va_cursor == segment["virtual_address"] + segment["decoded_size"]
    assert len(deep["functions"]) == decomp["function_count"] == decomp["completed_count"] == 300
    assert set(read("deep-selected-functions.json")) == {f["name"] for f in deep["functions"]}
    functions = {f["address"]: f for f in deep["functions"]}
    assert len(functions) == 300
    for f in deep["functions"]:
        assert f["candidate_end"] - f["address"] == f["size"]
        assert all(f["address"] <= e["site"] < f["candidate_end"] and e["site"] % 4 == 0 for e in f["transfers"])
    for f in decomp["functions"]:
        assert f["completed"] and not f["timed_out"]
        assert functions[f["address"]]["name"] == f["name"]
        assert functions[f["address"]]["size"] == f["candidate_body_bytes"]
    assert decomp["analysis_elf_sha256"] == math["analysis_elf_sha256"]
    assert len(math["cases"]) == 6
    for case in math["cases"]:
        assert case["passed"] and case["actual"] == case["expected"] == reference(case["left"], case["right"], case["shift"])
    assert len(read("comparison.json")["rows"]) == 18
    verify_html(ROOT / "deep-report.html", build_deep)
    verify_html(ROOT / "routing-report.html", build_routing)
    verify_routing()
    if firmware is not None:
        from q7_symbols import recover
        from decode_segments import inspect as decode
        from trace_q7 import trace
        from build_analysis_elf import assemble, PLAIN, DECODED
        import hashlib
        actual_symbols, _ = recover(firmware)
        assert actual_symbols == symbols, "symbol recovery mismatch"
        actual_decode, outputs = decode(firmware)
        assert actual_decode == decoded, "compressed block recovery mismatch"
        verify_routing(firmware, outputs)
        assert trace(firmware, read("deep-selected-functions.json"), outputs) == deep, "deep transfer mismatch"
        assert trace(firmware, read("selected-functions.json")) == read("threadx-shutter-transfers.json")
        segments = [(va, firmware[offset:offset+size]) for offset,va,size in PLAIN]
        segments += [(va, outputs[name[:-4]]) for name,va,size in DECODED]
        assert hashlib.sha256(assemble(segments)).hexdigest() == decomp["analysis_elf_sha256"]
        print("Original firmware: symbols, 448 blocks, 300 function hashes/transfers and analysis ELF reproduced")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--firmware", type=Path)
    args = parser.parse_args()
    evidence = json.loads((ROOT / "analysis/evidence.json").read_text(encoding="utf-8"))
    provenance = json.loads((ROOT / "analysis/provenance.json").read_text(encoding="utf-8"))
    assert provenance["byte_identical"]
    assert evidence["input_sha256"] == provenance["member_sha256"] == provenance["supplied_sha256"]
    assert evidence["input_size"] == provenance["member_size"]
    assert evidence["elf_magic_count"] == evidence["accepted_elf_count"] + len(evidence["rejected_candidates"])
    assert evidence["accepted_elf_count"] == len(evidence["elfs"]) == 12
    assert all(e["machine"] == 8 and e["elf_class"] == 32 for e in evidence["elfs"])
    assert sum(e["symbol_count"] for e in evidence["elfs"]) == 2569
    assert sum(e["defined_function_symbol_count"] for e in evidence["elfs"]) == 1504
    assert sum(w["size"] for w in evidence["entropy_windows"]) == evidence["input_size"]
    assert all(0 <= w["entropy"] <= 8 for w in evidence["entropy_windows"])
    verify_html(ROOT / "index.html", build)
    firmware = args.firmware.read_bytes() if args.firmware else None
    verify_deep(firmware)
    if args.firmware:
        recalculated, _ = inspect(firmware)
        assert recalculated == evidence, "full evidence reproduction mismatch"
        print("Original firmware: every published inventory field reproduced")
    print("Published evidence, deterministic HTML, image alt text and local links: PASS")


if __name__ == "__main__":
    main()
