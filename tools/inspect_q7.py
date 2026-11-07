"""Read-only ELF32/MIPS inventory of a caller-supplied Q7 update; Python stdlib only.

All file ranges are half-open. A referenced extent is NOT a container boundary.
ELF field definitions: https://gabi.xinuos.com/elf/02-eheader.html
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct

from pentax_lz import decode


def digest(data):
    return hashlib.sha256(data).hexdigest()


def checked(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError(f"range outside input: {offset:#x}+{size:#x}")
    return data[offset:offset + size]


def cstring(data, offset):
    if not 0 <= offset < len(data):
        raise ValueError("string index outside string table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated string-table entry")
    return data[offset:end].decode("utf-8", "replace")


def parse_elf(data, base):
    header = checked(data, base, 52)
    if header[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("not ELF32 little-endian version 1")
    (kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phsize, phnum, shsize, shnum, shstr) = struct.unpack_from("<HHIIIIIHHHHHH", header, 16)
    if kind not in (1, 2, 3) or machine != 8 or version != 1 or ehsize != 52:
        raise ValueError("unsupported ELF header")
    if phnum == 0xffff or shstr == 0xffff or (shoff and not shnum):
        raise ValueError("extended ELF indexes unsupported")
    if (phnum and (phsize != 32 or phoff < 52)) or (shnum and (shsize != 40 or shoff < 52)):
        raise ValueError("invalid ELF table shape")
    if phnum > 4096 or shnum > 4096:
        raise ValueError("table budget exceeded")
    extent = 52
    segments, sections, symbols, warnings = [], [], [], []
    for i in range(phnum):
        raw = checked(data, base + phoff + i * 32, 32)
        typ, off, va, pa, filesz, memsz, pf, align = struct.unpack("<8I", raw)
        checked(data, base + off, filesz)
        if typ == 1 and filesz > memsz:
            raise ValueError("PT_LOAD filesz exceeds memsz")
        if align not in (0, 1) and (align & (align - 1)):
            warnings.append(f"segment {i}: non-power-of-two alignment")
        if typ == 1 and align > 1 and (va - off) % align:
            warnings.append(f"segment {i}: load offset/address alignment mismatch")
        segments.append(dict(index=i, type=typ, relative_offset=off,
                             file_offset=base + off, virtual_address=va,
                             physical_address=pa, file_size=filesz,
                             memory_size=memsz, flags=pf, alignment=align))
        extent = max(extent, off + filesz, phoff + (i + 1) * 32)
    for i in range(shnum):
        values = struct.unpack("<10I", checked(data, base + shoff + i * 40, 40))
        name, typ, sf, va, off, size, link, info, align, entsize = values
        if typ != 8:
            checked(data, base + off, size)
            extent = max(extent, off + size)
        sections.append(dict(index=i, name_index=name, type=typ, flags=sf,
                             virtual_address=va, relative_offset=off,
                             file_offset=base + off, size=size, link=link,
                             info=info, alignment=align, entry_size=entsize))
        extent = max(extent, shoff + (i + 1) * 40)
    if sections:
        if shstr >= shnum:
            raise ValueError("section-name table index outside table")
        if shstr:
            table = sections[shstr]
            if table["type"] != 3:
                raise ValueError("section-name table is not STRTAB")
            names = checked(data, table["file_offset"], table["size"])
            for section in sections:
                section["name"] = cstring(names, section.pop("name_index"))
        else:
            for section in sections:
                section["name"] = ""
                section.pop("name_index")
    elif shstr:
        warnings.append(f"section table absent but e_shstrndx={shstr}; preserved as producer quirk")
    for section in sections:
        if section["type"] not in (2, 11):
            continue
        if section["entry_size"] != 16 or section["size"] % 16 or section["link"] >= shnum:
            raise ValueError("invalid symbol-table layout")
        if section["size"] // 16 > 1000000:
            raise ValueError("symbol budget exceeded")
        strings = sections[section["link"]]
        if strings["type"] != 3:
            raise ValueError("symbol strings not STRTAB")
        names = checked(data, strings["file_offset"], strings["size"])
        for off in range(section["file_offset"], section["file_offset"] + section["size"], 16):
            name, value, size, info, other, ndx = struct.unpack_from("<IIIBBH", data, off)
            symbols.append(dict(name=cstring(names, name), value=value, size=size,
                                type=info & 15, binding=info >> 4, section_index=ndx))
    entry_locations = [s["file_offset"] + entry - s["virtual_address"] for s in segments
                       if s["type"] == 1 and s["virtual_address"] <= entry < s["virtual_address"] + s["file_size"]]
    # ET_REL values are section-relative; never turn them into runtime addresses.
    result = dict(offset=base, elf_type=kind, machine=machine, elf_class=32,
                  byte_order="little", entry=entry, flags=flags,
                  referenced_extent=extent, referenced_end=base + extent,
                  sha256_referenced_bytes=digest(checked(data, base, extent)),
                  entry_file_offsets=entry_locations, segments=segments, sections=sections,
                  symbol_count=len(symbols), defined_function_symbol_count=sum(
                      s["type"] == 2 and s["section_index"] != 0 for s in symbols),
                  symbol_type_counts={str(k): v for k, v in sorted(Counter(s["type"] for s in symbols).items())},
                  warnings=warnings)
    interesting = re.compile(r"^(_tx_initialize_kernel_enter|_tx_thread_create|_tx_thread_schedule|_fx_media_open|HceThreadXStart|.*(Jpeg|WhiteBalance|ColorSpace|Shutter|AutoFocus).*)$")
    result["selected_symbols"] = [s for s in symbols if interesting.match(s["name"])][:24]
    return result, symbols


def entropy(data):
    counts = Counter(data)
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in counts.values()) if data else 0.0


def inspect(data):
    if len(data) > 128 * 1024 * 1024:
        raise ValueError("input exceeds 128 MiB budget")
    candidates = [m.start() for m in re.finditer(re.escape(b"\x7fELF"), data)]
    if len(candidates) > 4096:
        raise ValueError("candidate budget exceeded")
    elfs, rejected, all_symbols = [], [], {}
    for offset in candidates:
        try:
            item, symbols = parse_elf(data, offset)
            elfs.append(item)
            all_symbols[f"{offset:08x}"] = symbols
        except (ValueError, struct.error) as exc:
            rejected.append(dict(offset=offset, reason=str(exc)))
    for item in elfs:
        item["contained_in"] = [x["offset"] for x in elfs if x["offset"] < item["offset"] and
                                item["referenced_end"] <= x["referenced_end"]]
    try:
        payload, end, blocks = decode(data)
        lz = dict(status="decoded", output_size=len(payload), stream_end=end, blocks=len(blocks))
    except ValueError as exc:
        lz = dict(status="rejected", offset=128, reason=str(exc))
    markers = []
    for needle in [b"ThreadX LX4180/Green Hills", b"FileX LX4180/Green Hills",
                   b"PENTAX Q7", b"ORION", b"KB538", b"77690"]:
        for m in re.finditer(re.escape(needle), data):
            markers.append(dict(text=needle.decode(), offset=m.start()))
    windows = [dict(offset=o, size=len(data[o:o+65536]), entropy=round(entropy(data[o:o+65536]), 6))
               for o in range(0, len(data), 65536)]
    return dict(schema_version=1, input_size=len(data), input_sha256=digest(data),
                coordinate_system="original-file byte offsets; all ranges end-exclusive",
                elf_magic_count=len(candidates), accepted_elf_count=len(elfs),
                elfs=elfs, rejected_candidates=rejected, markers=markers,
                k3_lz_probe=lz, entropy_window_size=65536, entropy_windows=windows,
                ascii_runs_min6=sum(1 for _ in re.finditer(rb"[ -~]{6,}", data)),
                limitations=["ELF extents are maximum file references, not proven container partitions.",
                             "ELF acceptance validates this parser's bounded subset, not complete ELF ABI conformance.",
                             "ELF machine and strings do not identify the physical SoC or prove execution.",
                             "Entropy does not distinguish encryption, compression, code or media by itself.",
                             "No update checksum, signature, runtime behavior or flashing was verified."]), all_symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-dir", type=Path)
    args = parser.parse_args()
    if args.output.exists() or (args.private_dir and args.private_dir.exists()):
        parser.error("output and private directory must be new")
    if args.input.stat().st_size > 128 * 1024 * 1024:
        parser.error("input exceeds 128 MiB budget")
    data = args.input.read_bytes()
    report, symbols = inspect(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.private_dir:
        args.private_dir.mkdir(parents=True)
        (args.private_dir / "symbols.json").write_text(json.dumps(symbols, ensure_ascii=False), encoding="utf-8")
        for item in report["elfs"]:
            (args.private_dir / f"elf_{item['offset']:08x}.elf").write_bytes(data[item["offset"]:item["referenced_end"]])
    print(json.dumps({k: report[k] for k in ("input_size", "input_sha256", "elf_magic_count", "accepted_elf_count", "k3_lz_probe")}, indent=2))


if __name__ == "__main__":
    main()
