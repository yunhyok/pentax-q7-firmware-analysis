"""Decode the four Q7 v1.01 hardware-inflate PT_LOAD streams offline.

Input and output ranges are half-open. A compressed block maps to a decoded
address interval; individual compressed bytes do not have a linear VA.
"""
import argparse
import json
import struct
from pathlib import Path

from inspect_q7 import checked, digest, parse_elf


# ELF header offsets and names from analysis/evidence.json.
ELFS = ((0x2402c0, ("E04",)), (0x44c204, ("E05",)),
        (0x5ce660, ("E06-text", "E06-data")))
HEADER = struct.Struct("<IIIHH")
MAX_FIRMWARE = 128 * 1024 * 1024
MAX_OUTPUT = 16 * 1024 * 1024
BITS = tuple(f"{n:08b}" for n in range(256))


def decode_block(literal_table, distance_table, data, output, size):
    """Append one block; earlier blocks in this segment supply LZ history."""
    bits = "".join(BITS[value] for value in data)
    cursor = 0
    end = len(output) + size

    def peek(width):
        if not 0 <= width <= len(bits) - cursor:
            raise ValueError("truncated bitstream or invalid width")
        return int(bits[cursor:cursor + width], 2) if width else 0

    def take(width):
        nonlocal cursor
        value = peek(width)
        cursor += width
        return value

    def symbol(table, is_literal):
        nonlocal cursor
        word = table[0]
        for _ in range(16):
            kind = word & 3
            shift = word >> 15
            if kind == 3:
                # The literal/length leaf shift already counts its extra bits.
                extra = (word >> 12) & 7 if is_literal else 0
                take(shift - extra)
                return word & 0x7fff
            width = (word >> 11) & 15
            base = (word & 0x7ff) >> 2
            if kind == 0 and 0 <= shift <= width and width:
                # Dense lookup: leaf shift is relative to the minimum depth.
                index = base + peek(width)
                if index >= len(table):
                    raise ValueError("dense lookup outside table")
                word = table[index]
                take(shift if word & 3 == 3 else width)
            elif kind == 1 and width and 1 <= shift <= 15:
                # Compact lookup: count leading equal bits, up to the cap
                # for that bit, then consume the opposite bit if reached.
                side = take(1)
                cap = shift if side else width
                base += width if side else 0
                for count in range(1, cap + 1):
                    if count == cap or take(1) != side:
                        break
                index = base + count
                if index >= len(table):
                    raise ValueError("compact lookup outside table")
                word = table[index]
            else:
                raise ValueError("invalid Huffman descriptor")
        raise ValueError("Huffman lookup depth exceeded")

    while True:
        word = symbol(literal_table, True)
        if word == 0x403:
            if len(output) != end:
                raise ValueError("block output length mismatch")
            if "1" in bits[cursor:]:
                raise ValueError("nonzero padding after end marker")
            return cursor
        if len(output) >= end:
            raise ValueError("missing end marker at declared output length")
        if word < 0x400:
            output.append(word >> 2)
            continue
        if not word & 0x800 or word >> 12 > 5:
            raise ValueError("invalid length symbol")
        length = ((word >> 2) & 0x1ff) + take(word >> 12)
        if not 3 <= length <= min(258, end - len(output)):
            raise ValueError("copy length outside block output bound")
        word = symbol(distance_table, False)
        extra = word >> 4
        if extra > 13 or (extra and not word & 8):
            raise ValueError("invalid distance symbol")
        distance = (((word >> 2) & 3) << extra) + 1 + take(extra)
        if distance > len(output):
            raise ValueError("copy distance exceeds available history")
        history = output[-distance:]
        output.extend((history * ((length + distance - 1) // distance))[:length])


def decode_segment(data, segment):
    file_start = segment["file_offset"]
    file_end = file_start + segment["file_size"]
    va = segment["virtual_address"]
    size = segment["memory_size"]
    if not 0 < size <= MAX_OUTPUT:
        raise ValueError("segment exceeds output budget")
    checked(data, file_start, segment["file_size"])
    output = bytearray()
    blocks = []
    cursor = file_start
    while cursor < file_end:
        if file_end - cursor < HEADER.size:
            raise ValueError("truncated block header")
        kind, decoded, packed, literals, distances = HEADER.unpack_from(data, cursor)
        if kind != 2 or not 0 < decoded <= size - len(output):
            raise ValueError(f"invalid block type or output length at {cursor:#x}")
        if not 0 < packed <= 65536 or not literals or not distances or (literals | distances) & 3:
            raise ValueError(f"invalid table or payload length at {cursor:#x}")
        literal_start = cursor + HEADER.size
        distance_start = literal_start + literals
        bit_start = distance_start + distances
        next_cursor = bit_start + packed
        if next_cursor > file_end:
            raise ValueError(f"block exceeds segment file range at {cursor:#x}")
        literal_table = struct.unpack_from(f"<{literals // 4}I", data, literal_start)
        distance_table = struct.unpack_from(f"<{distances // 4}I", data, distance_start)
        va_start = va + len(output)
        try:
            used_bits = decode_block(literal_table, distance_table, data[bit_start:next_cursor],
                                     output, decoded)
        except ValueError as exc:
            raise ValueError(f"block at {cursor:#x}: {exc}") from exc
        blocks.append({"file_offset": cursor, "file_end": next_cursor,
                       "virtual_address": va_start, "virtual_end": va + len(output),
                       "literal_table_bytes": literals, "distance_table_bytes": distances,
                       "bitstream_offset": bit_start, "used_bits": used_bits})
        cursor = next_cursor
    if len(output) != size:
        raise ValueError("segment output length does not match ELF p_memsz")
    return bytes(output), blocks


def inspect(data):
    report = {
        "schema_version": 1,
        "input_sha256": digest(data),
        "input_size": len(data),
        "format": "Q7 v1.01 type-2 hardware-inflate blocks",
        "coordinate_system": "File offsets refer to the original update; decoded VAs are from ELF PT_LOAD. Ranges are half-open.",
        "firmware_evidence": [
            {"virtual_address": "0x800faf08", "file_offset": "0x1fd1f0",
             "observation": "InflateStreamData buffers a 16-byte block header."},
            {"virtual_address": "0x800faf78", "file_offset": "0x1fd260",
             "observation": "Stream reader loads table byte counts as u16 at +0xc/+0xe."},
            {"virtual_address": "0x800fb00c", "file_offset": "0x1fd2f4",
             "observation": "Stream reader includes the u32 at +0x8 in the input bound and transfers the payload in 128-byte units."},
            {"virtual_address": "0x800f9ff4", "file_offset": "0x1fc2dc",
             "observation": "InflateProcessor writes table data and metadata to the 0xb9800000 MMIO range."},
        ],
        "validation": ["All blocks consume their declared file ranges and reach the end marker at the declared decoded size.",
                       "Only zero padding follows each block's end marker.",
                       "Each decoded segment length equals p_memsz."],
        "limitations": ["The Huffman/LZ behavior is inferred from the table and bitstream, and checked by software decoding.",
                        "No execution on the camera, hardware byte comparison, or signature verification was performed.",
                        "E06-text is a filename for the RX PT_LOAD; the recovered bytes contain data as well as code."],
        "segments": [],
    }
    outputs = {}
    for offset, names in ELFS:
        elf, _ = parse_elf(data, offset)
        segments = [segment for segment in elf["segments"] if segment["type"] == 1]
        if len(segments) != len(names):
            raise ValueError(f"unexpected PT_LOAD count for ELF at {offset:#x}")
        for name, segment in zip(names, segments):
            decoded, blocks = decode_segment(data, segment)
            outputs[name] = decoded
            start = segment["file_offset"]
            end = start + segment["file_size"]
            report["segments"].append({
                "name": name, "elf_offset": offset, "segment_index": segment["index"],
                "file_offset": start, "file_end": end, "compressed_sha256": digest(data[start:end]),
                "virtual_address": segment["virtual_address"], "decoded_size": len(decoded),
                "decoded_sha256": digest(decoded), "block_count": len(blocks), "blocks": blocks,
            })
    return report, outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="new private directory for the decoded firmware and inventory")
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("output directory must not exist")
    with args.input.open("rb") as source:
        data = source.read(MAX_FIRMWARE + 1)
    if len(data) > MAX_FIRMWARE:
        parser.error("input exceeds 128 MiB budget")
    report, outputs = inspect(data)
    args.output_dir.mkdir(parents=True)
    for name, decoded in outputs.items():
        (args.output_dir / f"{name}.bin").write_bytes(decoded)
    (args.output_dir / "segment-decode.json").write_text(json.dumps(report, indent=2) + "\n",
                                                        encoding="utf-8")
    for entry in report["segments"]:
        print(f'{entry["name"]}: {entry["block_count"]} blocks, VA {entry["virtual_address"]:#x}, '
              f'{entry["decoded_size"]} bytes, sha256 {entry["decoded_sha256"]}')


if __name__ == "__main__":
    main()
