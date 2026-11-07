"""Create a synthetic, analysis-only MIPS ELF from original and decoded segments."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from q7_symbols import SHA

PLAIN = [(0x102774, 0x80000180, 416), (0x102914, 0x80000600, 340),
         (0x102A68, 0x80000780, 1233080), (0x22FB20, 0xBFC08000, 3908)]
DECODED = [("E04.bin", 0x8012DA80, 0x3F2300), ("E05.bin", 0x8051FE00, 0x2D2E00),
           ("E06-text.bin", 0x807F2C80, 0x36FF80), ("E06-data.bin", 0x80B62C00, 0x89780)]


def assemble(segments):
    offset = 52 + 32 * len(segments)
    headers, body = bytearray(), bytearray()
    for address, data in segments:
        headers += struct.pack("<8I", 1, offset, address, address, len(data), len(data), 7, 1)
        body += data
        offset += len(data)
    ident = b"\x7fELF\x01\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIIIIIHHHHHH", ident, 2, 8, 1, 0x80000600, 52, 0,
                         0x70001001, 52, 32, len(segments), 0, 0, 0)
    return header + headers + body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--decoded-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    data = args.firmware.read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA:
        parser.error("firmware hash mismatch")
    segments = [(va, data[off:off+size]) for off, va, size in PLAIN]
    manifest = json.loads((Path(__file__).resolve().parents[1] / "analysis/segment-decode.json").read_text())
    hashes = {s["name"]: s["decoded_sha256"] for s in manifest["segments"]}
    for name, va, size in DECODED:
        content = (args.decoded_dir / name).read_bytes()
        if len(content) != size or hashlib.sha256(content).hexdigest() != hashes[name[:-4]]:
            parser.error(f"decoded length or hash mismatch: {name}")
        segments.append((va, content))
    result = assemble(segments)
    args.output.write_bytes(result)
    print(json.dumps(dict(size=len(result), sha256=hashlib.sha256(result).hexdigest(),
                          role="synthetic analysis image; not a camera update")))


if __name__ == "__main__":
    main()
