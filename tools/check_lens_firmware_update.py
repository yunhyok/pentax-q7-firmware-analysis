"""Verify Q7 lens firmware update validation in Unicorn MIPS32LE against fwlq101.bin and fwlq102.bin."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / 'analysis/lens-firmware-update.json'

GET_CRC_BYTE_ADDR = 0x807DCEEC
EXECUTION_CHECK_ADDR = 0x807DCF48
LENS_ID_PLC_ADDR = 0x801122D8
FIRMUP_FILENAME_PLC_ADDR = 0x80112490
STRCAT_ADDR = 0x800FBC34
PRINTF_B_ADDR = 0x800A14F8
POOL_ALLOC_ADDR = 0x800EE804
POOL_FREE_ADDR = 0x800EE86C
FS_OPEN_ADDR = 0x8025FC7C
FS_SEEK_ADDR = 0x8025FDEC
FS_READ_ADDR = 0x8025FD60
FS_CLOSE_ADDR = 0x8025FC84

EXPECTED_HEADER_KEYS = (
    'filename', 'size_bytes', 'sha256', 'check_byte', 'format_tag_byte', 'lens_id',
    'lens_name', 'fw_version', 'fwup_model', 'lom_size', 'lom_offset',
    'lom_crc_header', 'lom_crc_computed', 'file_crc_trailer', 'file_crc_computed',
    'build_date', 'lens_version_string',
)


def crc16_ccitt_zero(data: bytes) -> int:
    """Reference CRC-16/CCITT (init=0, poly=0x1021) matching LensFirmwareUpdateService_GetCrc_BYTE."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def parse_lens_header(blob: bytes, filename: str) -> dict[str, Any]:
    if len(blob) < 0x100:
        raise ValueError(f'{filename}: lens image smaller than 256-byte header')
    lom_size, lom_offset, lom_crc_header = struct.unpack('>IIH', blob[0x28:0x32])
    if lom_offset + lom_size + 2 > len(blob):
        raise ValueError(f'{filename}: LOM range {lom_offset:#x}+{lom_size:#x} exceeds {len(blob)} bytes')
    lom_payload = blob[lom_offset:lom_offset + lom_size]
    file_crc_trailer = struct.unpack('>H', blob[-2:])[0]
    raw_ver = blob[0x80 + 64:0x80 + 78].split(b'\x00', 1)[0].decode('ascii', 'replace').strip()
    raw_date = blob[0x80 + 112:0x80 + 128].split(b'\x00', 1)[0].decode('ascii', 'replace').strip()
    return {
        'filename': filename,
        'size_bytes': len(blob),
        'sha256': sha256(blob).hexdigest(),
        'check_byte': blob[0],
        'format_tag_byte': blob[1],
        'lens_id': struct.unpack('>H', blob[2:4])[0],
        'lens_name': blob[4:32].split(b'\x00', 1)[0].decode('ascii', 'replace'),
        'fw_version': list(blob[0x22:0x26]),
        'fwup_model': struct.unpack('>H', blob[0x26:0x28])[0],
        'lom_size': lom_size,
        'lom_offset': lom_offset,
        'lom_crc_header': lom_crc_header,
        'lom_crc_computed': crc16_ccitt_zero(lom_payload),
        'file_crc_trailer': file_crc_trailer,
        'file_crc_computed': crc16_ccitt_zero(blob[:-2]),
        'build_date': raw_date,
        'lens_version_string': raw_ver,
    }


def _load_elf_segments(elf_path: Path) -> list[tuple[int, bytes]]:
    from elftools.elf.elffile import ELFFile
    segments: list[tuple[int, bytes]] = []
    with elf_path.open('rb') as handle:
        elf = ELFFile(handle)
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD':
                segments.append((int(seg['p_vaddr']), seg.data()))
    return segments


class _LensCheckHarness:
    """Minimal MIPS32LE Unicorn harness for LensFirmwareUpdateService_* routines."""

    RAM_SIZE = 0x04000000  # 64 MiB physical RAM (kseg0 0x80000000..0x83ffffff)
    HEAP_BASE = 0x82000000
    STACK_TOP = 0x83F00000
    HAL_RETURN = 0x83FF0000

    @staticmethod
    def _phys(addr: int) -> int:
        return addr & 0x1FFFFFFF

    def __init__(self, segments: list[tuple[int, bytes]]) -> None:
        from unicorn import Uc, UC_ARCH_MIPS, UC_MODE_MIPS32, UC_MODE_LITTLE_ENDIAN
        from unicorn.mips_const import UC_MIPS_REG_RA, UC_MIPS_REG_SP
        self.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN)
        self.segments = [(va, data) for va, data in segments if 0x80000000 <= va < 0x84000000]
        self.uc.mem_map(0, self.RAM_SIZE)
        self._reg_ra = UC_MIPS_REG_RA
        self._reg_sp = UC_MIPS_REG_SP
        self._reset_state()

    def _reset_state(self) -> None:
        for vaddr, data in self.segments:
            self.uc.mem_write(self._phys(vaddr), data)
        # Stub external ROM/RTOS calls with `jr $ra; nop` so Unicorn hooks only inspect args & set $v0.
        jr_ra_nop = struct.pack('<II', 0x03E00008, 0)
        for stub_addr in (
            FIRMUP_FILENAME_PLC_ADDR,
            LENS_ID_PLC_ADDR,
            STRCAT_ADDR,
            PRINTF_B_ADDR,
            POOL_ALLOC_ADDR,
            POOL_FREE_ADDR,
            FS_OPEN_ADDR,
            FS_SEEK_ADDR,
            FS_READ_ADDR,
            FS_CLOSE_ADDR,
        ):
            self.uc.mem_write(self._phys(stub_addr), jr_ra_nop)
        # Clear scratch BSS region around 0x807eee00..0x807eff00 (0x807f0000 - 0x1200)
        self.uc.mem_write(self._phys(0x807EEE00), b'\x00' * 0x400)
        self.uc.mem_write(self._phys(self.HEAP_BASE), b'\x00' * 0x200000)
        self.heap_cursor = self.HEAP_BASE + 0x1000

    def _read_cstr(self, addr: int, limit: int = 256) -> str:
        raw = bytes(self.uc.mem_read(self._phys(addr), limit))
        return raw.split(b'\x00', 1)[0].decode('ascii', 'replace')

    def run_crc_byte(self, data: bytes) -> int:
        from unicorn.mips_const import UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_V0
        self._reset_state()
        buf_addr = self.heap_cursor
        self.uc.mem_write(self._phys(buf_addr), data)
        self.uc.reg_write(self._reg_sp, self.STACK_TOP)
        self.uc.reg_write(self._reg_ra, self.HAL_RETURN)
        self.uc.reg_write(UC_MIPS_REG_A0, len(data))
        self.uc.reg_write(UC_MIPS_REG_A1, buf_addr)
        self.uc.emu_start(GET_CRC_BYTE_ADDR, self.HAL_RETURN, count=100_000_000)
        return self.uc.reg_read(UC_MIPS_REG_V0)

    def run_execution_check(
        self,
        *,
        mounted_lens_id: int,
        card_filename: str,
        file_bytes: bytes | None,
    ) -> dict[str, Any]:
        from unicorn import UC_HOOK_CODE
        from unicorn.mips_const import (
            UC_MIPS_REG_A0, UC_MIPS_REG_A1, UC_MIPS_REG_A2, UC_MIPS_REG_A3,
            UC_MIPS_REG_RA, UC_MIPS_REG_SP, UC_MIPS_REG_V0,
        )

        self._reset_state()
        logs: list[str] = []
        open_fd: dict[str, int] = {'handle': 0x1001, 'pos': 0}
        allocs: list[int] = []

        def hook(uc, address, size, _user):
            if address == FIRMUP_FILENAME_PLC_ADDR:
                dst = uc.reg_read(UC_MIPS_REG_A0)
                raw = card_filename.encode('ascii')[:16].ljust(16, b'\x00')
                uc.mem_write(self._phys(dst), raw)
                uc.reg_write(UC_MIPS_REG_V0, 1)
            elif address == LENS_ID_PLC_ADDR:
                out_ptr = uc.reg_read(UC_MIPS_REG_A0)
                uc.mem_write(self._phys(out_ptr), struct.pack('<H', mounted_lens_id))
                uc.reg_write(UC_MIPS_REG_V0, 1)
            elif address == STRCAT_ADDR:
                dst = uc.reg_read(UC_MIPS_REG_A0)
                src = uc.reg_read(UC_MIPS_REG_A1)
                merged = (self._read_cstr(dst) + self._read_cstr(src)).encode('ascii') + b'\x00'
                uc.mem_write(self._phys(dst), merged)
                uc.reg_write(UC_MIPS_REG_V0, dst)
            elif address == PRINTF_B_ADDR:
                fmt_addr = uc.reg_read(UC_MIPS_REG_A0)
                a1 = uc.reg_read(UC_MIPS_REG_A1)
                a2 = uc.reg_read(UC_MIPS_REG_A2)
                fmt = self._read_cstr(fmt_addr).rstrip('\n')
                if '%s' in fmt:
                    logs.append(fmt.replace('%s', self._read_cstr(a1)))
                elif '%d. %d. %d. %d' in fmt:
                    a3 = uc.reg_read(UC_MIPS_REG_A3)
                    sp = uc.reg_read(UC_MIPS_REG_SP)
                    arg4 = struct.unpack('<I', uc.mem_read(self._phys(sp + 0x10), 4))[0]
                    logs.append(fmt % (a1, a2, a3, arg4))
                elif '%x' in fmt or '%d' in fmt:
                    logs.append(fmt % a1)
                else:
                    logs.append(fmt)
                uc.reg_write(UC_MIPS_REG_V0, 0)
            elif address == POOL_ALLOC_ADDR:
                req = uc.reg_read(UC_MIPS_REG_A1)
                ptr = self.heap_cursor
                self.heap_cursor = (self.heap_cursor + max(req, 16) + 0xFF) & ~0xFF
                allocs.append(req)
                uc.reg_write(UC_MIPS_REG_V0, ptr)
            elif address == POOL_FREE_ADDR:
                uc.reg_write(UC_MIPS_REG_V0, 0)
            elif address == FS_OPEN_ADDR:
                if file_bytes is None:
                    uc.reg_write(UC_MIPS_REG_V0, 0)
                else:
                    open_fd['pos'] = 0
                    uc.reg_write(UC_MIPS_REG_V0, open_fd['handle'])
            elif address == FS_SEEK_ADDR:
                # o32 ABI DirectFsFileRelSeek(int fd, int pad, int64_t offset, int whence): $a2 holds low 32 bits of offset.
                open_fd['pos'] = uc.reg_read(UC_MIPS_REG_A2)
                uc.reg_write(UC_MIPS_REG_V0, 0)
            elif address == FS_READ_ADDR:
                buf = uc.reg_read(UC_MIPS_REG_A1)
                nbytes = uc.reg_read(UC_MIPS_REG_A2)
                if file_bytes is None:
                    uc.reg_write(UC_MIPS_REG_V0, 0)
                else:
                    pos = open_fd['pos']
                    chunk = file_bytes[pos:pos + nbytes]
                    uc.mem_write(self._phys(buf), chunk)
                    open_fd['pos'] = pos + len(chunk)
                    uc.reg_write(UC_MIPS_REG_V0, len(chunk))
            elif address == FS_CLOSE_ADDR:
                uc.reg_write(UC_MIPS_REG_V0, 0)

        h = self.uc.hook_add(UC_HOOK_CODE, hook, begin=0x80000000, end=0x80FFFFFF)
        try:
            self.uc.reg_write(UC_MIPS_REG_SP, self.STACK_TOP)
            self.uc.reg_write(UC_MIPS_REG_RA, self.HAL_RETURN)
            self.uc.emu_start(EXECUTION_CHECK_ADDR, self.HAL_RETURN, count=100_000_000)
            rv = self.uc.reg_read(UC_MIPS_REG_V0)
        finally:
            self.uc.hook_del(h)

        return {
            'return_value': rv,
            'alloc_sizes': allocs,
            'logs': logs,
        }


def run_verification(firmware_path: Path, elf_path: Path, lens_paths: list[Path]) -> dict[str, Any]:
    fw_bytes = firmware_path.read_bytes()
    elf_bytes = elf_path.read_bytes()
    segments = _load_elf_segments(elf_path)
    harness = _LensCheckHarness(segments)

    lens_headers: list[dict[str, Any]] = []
    lens_blobs: list[bytes] = []
    for lp in lens_paths:
        blob = lp.read_bytes()
        lens_blobs.append(blob)
        info = parse_lens_header(blob, lp.name)
        info['emu_file_crc'] = harness.run_crc_byte(blob[:-2])
        info['emu_lom_crc'] = harness.run_crc_byte(blob[info['lom_offset']:info['lom_offset'] + info['lom_size']])
        assert info['emu_file_crc'] == info['file_crc_computed'] == info['file_crc_trailer']
        assert info['emu_lom_crc'] == info['lom_crc_computed'] == info['lom_crc_header']
        lens_headers.append(info)

    b1 = lens_blobs[0]
    b2 = lens_blobs[1] if len(lens_blobs) > 1 else lens_blobs[0]
    bad_crc = bytearray(b1)
    bad_crc[0x100] ^= 0x01
    bad_check_byte = bytearray(b1)
    bad_check_byte[0] = 0x01

    specs = [
        ('fwlq101_valid', b1, 1, lens_paths[0].name, b1),
        ('fwlq102_valid', b2, 2, (lens_paths[1] if len(lens_paths) > 1 else lens_paths[0]).name, b2),
        ('lens_id_mismatch', b1, 2, lens_paths[0].name, b1),
        ('file_crc_mismatch', b1, 1, lens_paths[0].name, bytes(bad_crc)),
        ('check_byte_nonzero', b1, 1, lens_paths[0].name, bytes(bad_check_byte)),
        ('file_open_failed', b1, 1, lens_paths[0].name, None),
    ]
    cases = []
    for name, _orig, lens_id, card_fn, data in specs:
        res = harness.run_execution_check(mounted_lens_id=lens_id, card_filename=card_fn, file_bytes=data)
        cases.append({
            'case': name,
            'mounted_lens_id': lens_id,
            'card_filename': card_fn,
            'return_value': res['return_value'],
            'alloc_sizes': res['alloc_sizes'],
            'logs': res['logs'],
        })

    return {
        'firmware': {
            'file': firmware_path.name,
            'sha256': sha256(fw_bytes).hexdigest(),
            'main_elf_sha256': sha256(elf_bytes).hexdigest(),
        },
        'routines': {
            'GetCrc_BYTE': hex(GET_CRC_BYTE_ADDR),
            'UserLensFirmwareUpdateExecutionCheck': hex(EXECUTION_CHECK_ADDR),
            'GetLensFirmupFileNamePLC': hex(FIRMUP_FILENAME_PLC_ADDR),
            'GetLensIdPLC': hex(LENS_ID_PLC_ADDR),
            'UserLensFirmwareUpdateExecution': '0x807ddc58',
        },
        'crc_algorithm': {'name': 'CRC-16/CCITT-XMODEM', 'poly': '0x1021', 'init': '0x0000'},
        'lens_images': lens_headers,
        'execution_check_cases': cases,
        'scope': {
            'emulated_crc_and_execution_check': True,
            'lens_rom_crc_header_checked_via_getcrc': True,
            'actual_lens_communication_or_flash_write': False,
            'firmware_bytes_exported': False,
        },
    }


def validate_report(record: dict[str, Any]) -> dict[str, Any]:
    images = record.get('lens_images', [])
    if len(images) < 2:
        raise ValueError('expected at least 2 lens image records (fwlq101.bin and fwlq102.bin)')
    for img in images:
        missing = [k for k in EXPECTED_HEADER_KEYS if k not in img]
        if missing:
            raise ValueError(f'{img.get("filename")}: missing keys {missing}')
        if img['file_crc_trailer'] != img['file_crc_computed'] or img['emu_file_crc'] != img['file_crc_trailer']:
            raise ValueError(f'{img["filename"]}: file CRC mismatch')
        if img['lom_crc_header'] != img['lom_crc_computed'] or img['emu_lom_crc'] != img['lom_crc_header']:
            raise ValueError(f'{img["filename"]}: LOM CRC mismatch')
    by_case = {c['case']: c for c in record.get('execution_check_cases', [])}
    expected_rv = {
        'fwlq101_valid': 1,
        'fwlq102_valid': 1,
        'lens_id_mismatch': 0,
        'file_crc_mismatch': 0,
        'check_byte_nonzero': 0,
        'file_open_failed': 0,
    }
    if set(by_case) != set(expected_rv):
        raise ValueError(f'unexpected execution check cases: {sorted(by_case)}')
    for name, rv in expected_rv.items():
        if by_case[name]['return_value'] != rv:
            raise ValueError(f'case {name}: expected return {rv}, got {by_case[name]["return_value"]}')
    if '[LENS ID] AGREEMENT' not in by_case['fwlq101_valid']['logs'] or '[FILE_CRC] AGREEMENT' not in by_case['fwlq101_valid']['logs']:
        raise ValueError('fwlq101_valid missing expected agreement log markers')
    if '[LENS ID] DISAGREEMENT' not in by_case['lens_id_mismatch']['logs']:
        raise ValueError('lens_id_mismatch missing DISAGREEMENT log')
    if '[FILE_CRC] DISAGREEMENT' not in by_case['file_crc_mismatch']['logs']:
        raise ValueError('file_crc_mismatch missing DISAGREEMENT log')
    if 'FILE OPEN FAILED! HEADER' not in by_case['file_open_failed']['logs']:
        raise ValueError('file_open_failed missing FILE OPEN FAILED! HEADER log')
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firmware', type=Path, help='Original fwdc603p.bin path')
    parser.add_argument('--elf', type=Path, default=ROOT / '.private/main-expanded.elf', help='Decoded main ELF path')
    parser.add_argument('--lens', type=Path, nargs='+', help='Lens update files (e.g. fwlq101.bin fwlq102.bin)')
    parser.add_argument('--output', type=Path, help='Write JSON report')
    parser.add_argument('--check', type=Path, default=DEFAULT_OUTPUT, help='Compare or validate JSON report')
    args = parser.parse_args()

    if args.firmware and args.lens:
        record = run_verification(args.firmware, args.elf, args.lens)
        validate_report(record)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(record, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        if args.check.exists() and (not args.output or args.check.resolve() != args.output.resolve()):
            published = json.loads(args.check.read_text(encoding='utf-8'))
            if published != record:
                raise SystemExit('Mismatch against published analysis/lens-firmware-update.json')
        print(f'Lens firmware check OK: {len(record["lens_images"])} images, {len(record["execution_check_cases"])} emulated cases')
        return 0

    record = json.loads(args.check.read_text(encoding='utf-8'))
    validate_report(record)
    print(f'Published lens firmware evidence valid: {len(record["lens_images"])} images, {len(record["execution_check_cases"])} cases')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
