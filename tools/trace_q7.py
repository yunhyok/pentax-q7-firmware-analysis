"""Bounded MIPS32 direct-transfer evidence from Q7's uncompressed main ELF."""
import argparse
import bisect
import hashlib
import json
import struct
from pathlib import Path
from q7_symbols import recover

ROOT = Path(__file__).resolve().parents[1]
BASE, OFFSET, SIZE = 0x80000780, 0x102A68, 1233080


def transfer(word, pc):
    opcode = word >> 26
    if opcode in (2, 3):
        return ("call" if opcode == 3 else "jump", ((pc + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2))
    if opcode == 1 and (word >> 16) & 31 in (16, 17, 18, 19):
        immediate = word & 0xFFFF
        return "conditional-call", pc + 4 + (immediate - (0x10000 if immediate & 0x8000 else 0)) * 4
    if opcode == 0 and word & 63 == 9:
        return "indirect-call", None
    if opcode == 0 and word & 63 == 8 and (word >> 21) & 31 != 31:
        return "indirect-jump", None
    return None


def trace(data, selected, decoded=None):
    summary, symbols = recover(data)
    names = {s["name"]: s["address"] for s in symbols}
    labels = {}
    for s in symbols:
        labels.setdefault(s["address"], []).append(s["name"])
    addresses = sorted(labels)
    functions = []
    for name in selected:
        start = names[name]
        end = addresses[bisect.bisect_right(addresses, start)]
        location = {}
        if BASE <= start < end <= BASE + SIZE:
            offset = start - BASE + OFFSET
            body = data[offset:offset + end - start]
            location = dict(file_offset=offset)
        elif decoded:
            from build_analysis_elf import DECODED
            for filename, va, size in DECODED:
                if va <= start < end <= va + size:
                    body = decoded[filename[:-4]][start-va:end-va]
                    location = dict(segment=filename[:-4], decoded_offset=start-va)
                    break
        if not location or (start | end) & 3:
            raise ValueError(f"not a bounded main MIPS32 extent: {name}")
        edges = []
        for pos in range(0, len(body), 4):
            pc = start + pos
            word = struct.unpack_from("<I", body, pos)[0]
            item = transfer(word, pc)
            if item:
                kind, target = item
                if kind == "jump" and start <= target < end:
                    continue
                edges.append(dict(site=pc, word=f"{word:08x}", kind=kind, target=target,
                                  target_names=labels.get(target, [])))
        functions.append(dict(name=name, address=start, candidate_end=end, **location,
                              size=len(body), sha256=hashlib.sha256(body).hexdigest(), transfers=edges))
    return dict(input_sha256=summary["input_sha256"], functions=functions,
                limitations=["Extents end at the next distinct sidecar address, not a typed ELF function size.",
                             "Linear MIPS32 word scan; edges are instruction candidates, not proof of reachability.",
                             "Delay slots are included in extents. Register-indirect targets are unresolved.",
                             "A jump is recorded as a transfer, not automatically a function call."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--selected", type=Path, default=ROOT / "analysis/selected-functions.json")
    parser.add_argument("--decoded-dir", type=Path)
    parser.add_argument("--ghidra-dir", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    selected = json.loads(args.selected.read_text())
    decoded = None
    if args.decoded_dir:
        manifest = json.loads((ROOT / "analysis/segment-decode.json").read_text())
        decoded = {}
        for segment in manifest["segments"]:
            content = (args.decoded_dir / (segment["name"] + ".bin")).read_bytes()
            if hashlib.sha256(content).hexdigest() != segment["decoded_sha256"]:
                parser.error("decoded segment hash mismatch")
            decoded[segment["name"]] = content
    data = args.firmware.read_bytes()
    result = trace(data, selected, decoded)
    if args.ghidra_dir:
        args.ghidra_dir.mkdir(parents=True, exist_ok=False)
        _, symbols = recover(data)
        (args.ghidra_dir / "symbols.tsv").write_text("".join(
            f"{s['address']:08x}\t{s['name']}\n" for s in symbols), encoding="utf-8")
        (args.ghidra_dir / "seeds.tsv").write_text("".join(
            f"{f['address']:08x}\t{f['candidate_end']:08x}\t{f['name']}\n"
            for f in result["functions"]), encoding="utf-8")
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"{len(result['functions'])} bounded function candidates")


if __name__ == "__main__":
    main()
