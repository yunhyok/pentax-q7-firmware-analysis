"""Recover Q7 main-address/name sidecars via their FAT16 root directory and chains.

The declared FAT volume extends past the update image. Only allocated, file-backed
chains are read; this is not a mount or a complete filesystem integrity check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from inspect_q7 import checked

SHA = "8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b"
VOLUME = 0x77C2C0


def sha(data):
    return hashlib.sha256(data).hexdigest()


def root_files(data, volume=VOLUME):
    boot = checked(data, volume, 512)
    bps, spc, reserved, fats, roots = struct.unpack_from("<HBHBH", boot, 11)
    spf = struct.unpack_from("<H", boot, 22)[0]
    total = struct.unpack_from("<H", boot, 19)[0] or struct.unpack_from("<I", boot, 32)[0]
    if boot[54:62] != b"FAT16   " or boot[510:512] != b"\x55\xaa":
        raise ValueError("not the expected FAT16 boot record")
    if bps not in (512, 1024, 2048, 4096) or not spc or spc & (spc - 1) or not (reserved and fats and spf):
        raise ValueError("invalid FAT geometry")
    fat_start = volume + reserved * bps
    root_start = volume + (reserved + fats * spf) * bps
    data_start = root_start + ((roots * 32 + bps - 1) // bps) * bps
    fat = checked(data, fat_start, spf * bps)
    directory = checked(data, root_start, roots * 32)
    entries = []
    for n in range(0, len(directory), 32):
        entry = directory[n:n + 32]
        if entry[0] == 0:
            break
        if entry[0] == 0xe5 or entry[11] == 15 or entry[11] & 0x18:
            continue
        name = entry[:8].decode("ascii").rstrip() + "." + entry[8:11].decode("ascii").rstrip()
        first = struct.unpack_from("<H", entry, 26)[0]
        size = struct.unpack_from("<I", entry, 28)[0]
        entries.append(dict(name=name, directory_offset=root_start + n, first_cluster=first, size=size))
    return dict(volume_offset=volume, sector_size=bps, sectors_per_cluster=spc,
                cluster_size=bps * spc, fat_start=fat_start, root_start=root_start,
                data_start=data_start, declared_volume_bytes=total * bps,
                declared_volume_exceeds_update=volume + total * bps > len(data)), entries, fat


def read_file(data, geometry, fat, entry):
    remaining, cluster = entry["size"], entry["first_cluster"]
    output, spans, seen = bytearray(), [], set()
    while remaining:
        if cluster < 2 or cluster >= 0xfff0 or cluster in seen or cluster * 2 + 2 > len(fat):
            raise ValueError("invalid, cyclic or premature FAT chain")
        seen.add(cluster)
        offset = geometry["data_start"] + (cluster - 2) * geometry["cluster_size"]
        size = min(remaining, geometry["cluster_size"])
        output.extend(checked(data, offset, size))
        if spans and spans[-1]["offset"] + spans[-1]["size"] == offset:
            spans[-1]["size"] += size
        else:
            spans.append(dict(offset=offset, size=size))
        remaining -= size
        cluster = struct.unpack_from("<H", fat, cluster * 2)[0]
    if entry["size"] and cluster < 0xfff8:
        raise ValueError("chain continues beyond declared file size")
    return bytes(output), spans


def decode_symbols(addresses, offsets, strings):
    if len(addresses) != len(offsets) or len(addresses) % 4:
        raise ValueError("address/offset arrays differ or are misaligned")
    rows = []
    previous_address = -1
    for n, ((address,), (offset,)) in enumerate(zip(struct.iter_unpack("<I", addresses), struct.iter_unpack("<I", offsets))):
        if not 0 <= offset < len(strings) or (offset and strings[offset - 1] != 0):
            raise ValueError("name offset is not at a string boundary")
        end = strings.find(b"\0", offset)
        if end < 0:
            raise ValueError("unterminated name")
        name = strings[offset:end].decode("ascii")
        if not name or any(ord(c) < 32 or ord(c) > 126 for c in name):
            raise ValueError("invalid symbol name")
        if address < previous_address:
            raise ValueError("address table not sorted")
        previous_address = address
        rows.append(dict(index=n, address=address, name_offset=offset, name=name))
    return rows


def recover(data):
    if sha(data) != SHA:
        raise ValueError("expected original Q7 v1.01 SHA-256")
    geometry, entries, fat = root_files(data)
    sources, contents = [], []
    for suffix in ("ADR", "OFT", "STR"):
        choices = [e for e in entries if e["name"].startswith("MAINSO~") and e["name"].endswith("." + suffix)]
        if len(choices) != 1:
            raise ValueError("main sidecar not unique")
        entry = choices[0]
        content, spans = read_file(data, geometry, fat, entry)
        sources.append({**entry, "sha256": sha(content), "file_spans": spans})
        contents.append(content)
    rows = decode_symbols(*contents)
    summary = dict(input_sha256=SHA, geometry=geometry, sources=sources,
                   symbol_records=len(rows), unique_addresses=len({r["address"] for r in rows}),
                   unique_names=len({r["name"] for r in rows}),
                   all_names_bounded_and_ascii=True, addresses_nondecreasing=True,
                   limitations=["Address/name records carry no ELF symbol type or function size.",
                                "Duplicate addresses and data labels are retained; records are not a function count.",
                                "Only allocated root file chains used by the three sidecars were verified."])
    return summary, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-symbols", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.private_symbols.exists():
        parser.error("outputs must not exist")
    summary, rows = recover(args.firmware.read_bytes())
    for path, value in ((args.output, summary), (args.private_symbols, rows)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: summary[k] for k in ["symbol_records", "unique_addresses", "unique_names"]}))


if __name__ == "__main__":
    main()
