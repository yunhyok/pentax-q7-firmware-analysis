"""Repack the pinned reconstructed Q13 object into a private Q7 research image."""
import argparse
from io import BytesIO
import json
from pathlib import Path

from check_recompiled_numeric import (BUILD, ELF_SHA256, FIRMWARE_SHA256, OBJECT_SHA256,
    ORIGINAL, RECOMPILED_SIZE, TEXT_SHA256, digest, load_segment_offset, overlay, read_pinned, require)
from decode_segments import inspect
from repack_q7 import private_output, rebuild, write_outputs

UPDATE_SHA256 = 'eb5d014b761f947b2bd1786651c56d039db8e0e281b7e96c5a8c79a93ad978d6'
REBUILT_ELF_SHA256 = 'e2ee3f210e36fea1f69442f9a167f5090334a9c22a725fb913596004af3b0512'


def verify(firmware_path, elf_path, object_path):
    firmware = read_pinned(firmware_path, FIRMWARE_SHA256)
    original = read_pinned(elf_path, ELF_SHA256)
    obj = read_pinned(object_path, OBJECT_SHA256)
    from elftools.elf.elffile import ELFFile
    code = ELFFile(BytesIO(obj)).get_section_by_name(BUILD['text_section']).data()
    require(len(code) == RECOMPILED_SIZE and digest(code) == TEXT_SHA256, 'unexpected compiled text')
    expected = overlay(firmware, original, code, ELFFile)
    offset = load_segment_offset(ELFFile(BytesIO(original)), ORIGINAL, len(code))
    plan = [dict(va=hex(ORIGINAL), expected_hex=original[offset:offset+len(code)].hex(),
                 replacement_hex=code.hex(), label='reconstructed Q13 arithmetic leaf')]
    package, elf, report = rebuild(firmware, plan)
    require(elf == expected, 'redecoded image differs from the natively replayed C overlay')
    require(digest(package) == UPDATE_SHA256 and digest(elf) == REBUILT_ELF_SHA256,
            'unexpected fixed-table research artifact')
    manifest, _ = inspect(firmware)
    changed = [(s['name'], c) for s in report['segment_results'] for c in s['changed_blocks']]
    require([(name, c['block']) for name,c in changed] == [('E04',154),('E04',155)], 'unexpected changed blocks')
    blocks = []
    for name, c in changed:
        segment = next(s for s in manifest['segments'] if s['name'] == name)
        block = segment['blocks'][c['block']]
        start, bit_start, end = (block[k] for k in ('file_offset','bitstream_offset','file_end'))
        require(firmware[start:bit_start] == package[start:bit_start], 'block header or table changed')
        blocks.append(dict(c, segment=name, virtual_address=hex(block['virtual_address']),
                           virtual_end=hex(block['virtual_end']), capacity_bytes=end-bit_start,
                           used_bytes=(c['new_bits']+7)//8, zero_tail_bits=(end-bit_start)*8-c['new_bits'],
                           header_and_tables_sha256=digest(package[start:bit_start]),
                           payload_sha256=digest(package[bit_start:end])))
    e04 = next(s for s in report['segment_results'] if s['name'] == 'E04')
    result = dict(input_sha256=FIRMWARE_SHA256, object_sha256=OBJECT_SHA256, text_sha256=TEXT_SHA256,
                  output_sha256=UPDATE_SHA256, analysis_elf_sha256=REBUILT_ELF_SHA256,
                  output_size=len(package), patch_va=hex(ORIGINAL), patch_bytes=len(code),
                  decoded_difference_bytes=sum(a != b for a,b in zip(original,elf,strict=True)),
                  decoded_e04_sha256=e04['decoded_sha256'], blocks=blocks,
                  total_blocks=448, unchanged_blocks=446, segments=4,
                  image_equals_replayed_overlay=True, all_decoded_bytes_and_layout_verified=True,
                  footer_after=report['footer_after'],
                  limits=['Host software decoder and byte identity only; no camera hardware inflate or update acceptance.',
                          'Original tables, slots, ELF positions and file size retained; no general relocation or table regeneration.',
                          'The current fallback still requires literal codes and adequate space; unrepresentable or overflowing windows fail.'])
    report['numeric_validation'] = result
    return package, elf, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware', type=Path)
    parser.add_argument('elf', type=Path)
    parser.add_argument('object', type=Path)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        output = private_output(args.output_dir)
    except ValueError as exc:
        parser.error(str(exc))
    package, elf, report = verify(args.firmware, args.elf, args.object)
    write_outputs(output, package, elf, report)
    print(json.dumps(report['numeric_validation'], indent=2))


if __name__ == '__main__':
    main()
