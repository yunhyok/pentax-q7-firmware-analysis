"""Check published metadata, deterministic HTML, links and optional original firmware."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import urlparse, unquote

from inspect_q7 import inspect
from build_report import main as build

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
    page = ROOT / "index.html"
    before = page.read_bytes()
    build()
    assert page.read_bytes() == before, "committed HTML differs from generated report"
    html = before.decode("utf-8")
    links = Links()
    links.feed(html)
    assert len(links.ids) == len(set(links.ids)), "duplicate HTML ID"
    for link in links.links:
        url = urlparse(link)
        if url.scheme or url.netloc:
            assert url.scheme in ("https",), f"unexpected external scheme: {link}"
            continue
        path = unquote(url.path)
        assert ".private" not in path and "_workspace" not in path
        if path:
            target = (ROOT / path).resolve()
            assert target.is_relative_to(ROOT) and target.is_file(), f"broken local link: {link}"
        elif url.fragment:
            assert url.fragment in links.ids, f"broken anchor: {link}"
    assert "{{" not in html and "C:\\Users" not in html
    if args.firmware:
        recalculated, _ = inspect(args.firmware.read_bytes())
        assert recalculated == evidence, "full evidence reproduction mismatch"
        print("Original firmware: every published inventory field reproduced")
    print("Published evidence, deterministic HTML, image alt text and local links: PASS")


if __name__ == "__main__":
    main()
