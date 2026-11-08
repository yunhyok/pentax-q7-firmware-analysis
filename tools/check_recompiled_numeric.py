"""Compile reconstructed Q7 C and compare its MIPS text with the original Q13 routine."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
from random import Random
import struct
import subprocess

from check_color_math import reference as matrix_reference
from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP
from q7_symbols import SHA as FIRMWARE_SHA256


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "source/reconstructed/q7_numeric.c"
SOURCE_SHA256 = "283cfa0196de71d81e9ca8cbde3a68b5f24961bdb05cbce0fe667e7100414582"
ZIG_VERSION = "0.15.2"
ZIG_SHA256 = "d408dd38eed3e5204af841bcebf70502a4dbbb8399a3a3262be55059370bc018"
OBJECT_SHA256 = "6cb0cb595a4c1a67494ec15b997a87ea1d00d9fca3cf7229ed00beb90ab0e452"
TEXT_SHA256 = "eb28d55d4814fc0734c6c23fe3e977d5be17e39cc3d9a8c873559ff34d03f458"
LEAF_SHA256 = "5a8fe227ed47a9e1fa0a8a3484a542554ca44b4b00f8c734f7d90d2ea65c24d4"
CALLER_SHA256 = "eeed58c00b64bcc3c6217725ac1f68a9a39e679b8c46861437a906af46f5e6e4"
CC_ARGS = (
    "cc", "-target", "mipsel-freestanding-none", "-mcpu=mips32r2+noabicalls",
    "-mabi=o32", "-mfp32", "-fno-pic", "-G0", "-std=c11", "-ffreestanding",
    "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables", "-ffunction-sections", "-Oz",
    "-Wall", "-Wextra", "-Werror", "-c", "-x", "c", "-", "-o", "q7_numeric.o",
)
FUNCTION = "q7_matrix_mul_q13"
ORIGINAL, ORIGINAL_END = 0x8041BC90, 0x8041BD7C
HUE, CALLER, CALLER_END = 0x8041BE94, 0x8041C180, 0x8041C7DC
RECOMPILED_SIZE = 164
CARRIER_OFFSETS = (0x1026C0, 0x2402C0)
ELF_FLAGS = 0x70001001
ABI_FLAGS = (0, 32, 2, 1, 1, 0, 1, 0, 0, 1, 0)
BUILD = dict(
    source="source/reconstructed/q7_numeric.c", source_lf_sha256=SOURCE_SHA256,
    compiler_version=ZIG_VERSION, compiler_exe_sha256=ZIG_SHA256,
    llvm_build="clang version 20.1.2 (https://github.com/ziglang/zig-bootstrap 7ef74e656cf8ddbd6bf891a8475892aa1afa6891)",
    official_index="https://ziglang.org/download/index.json",
    windows_archive_sha256="3a0ed1e8799a2f8ce2a6e6290a9ff22e6906f8227865911fb7ddedc3cc14cb0c",
    command=["<verified zig.exe snapshot>", *CC_ARGS], source_via_stdin=True,
    object_sha256=OBJECT_SHA256, text_sha256=TEXT_SHA256,
    text_section=f".text.{FUNCTION}", text_size=RECOMPILED_SIZE,
    elf=dict(elf_class=32, byte_order="little", machine="EM_MIPS", type="ET_REL",
             flags=hex(ELF_FLAGS), isa_level=32, isa_revision=2, gpr_bits=32,
             fp_register_bits=32, fp_abi_attribute=1, unresolved_imports=0,
             code_relocations=0, metadata_relocations=[[".rel.pdr", ".pdr", 1]]),
)
ORIGINAL_INFO = dict(
    entry=hex(ORIGINAL), end_exclusive=hex(ORIGINAL_END), bytes=ORIGINAL_END - ORIGINAL,
    sha256=LEAF_SHA256, caller_entry=hex(CALLER), caller_end_exclusive=hex(CALLER_END),
    caller_sha256=CALLER_SHA256, embedded_elf_offsets=[hex(i) for i in CARRIER_OFFSETS],
    carrier_e_flags=hex(ELF_FLAGS), carrier_fp_abi_attribute=None,
    unchanged_tail_bytes=ORIGINAL_END - ORIGINAL - RECOMPILED_SIZE,
)
SEED = 804113
ARENA = 0x10000000
STACK_BASE = STACK_TOP - 0x300
INPUT, OUT2, OUT3, OUT5, SCRATCH = ARENA, ARENA + 0x1000, ARENA + 0x2000, ARENA + 0x3000, 0x80C53F80
SAVED = (*(f"s{i}" for i in range(8)), "s8", "gp", "sp", *(f"f{i}" for i in range(20, 32)))
LAYOUTS = (
    ("distinct", 0x12, 0x42, 0x72),
    ("out-is-left", 0x12, 0x40, 0x12),
    ("out-is-right", 0x10, 0x42, 0x42),
    ("out-overlaps-left-after", 0x10, 0x42, 0x12),
    ("out-overlaps-right-before", 0x12, 0x42, 0x40),
    ("both-inputs-are-same", 0x12, 0x12, 0x72),
    ("all-three-are-same", 0x12, 0x12, 0x12),
    ("three-partial-overlaps", 0x12, 0x16, 0x14),
)
CALLER_CASES = ((0, 0, 4, 4), (1, 0, 4, 4), (0, 1, 0, 8), (1, 2, 8, 0))
SCOPE = ("Two code images use the same verified Q7 ELF snapshot. The second changes only the "
         "selected leaf text at its original address in host memory. The leaf and four original "
         "MakeColorMatrix calls execute with VEX and synthetic RAM, using observation-only "
         "state.inspect hooks and no function stubs or behavior substitutions. No device is used.")
MACHINE_STATE = dict(case="positive-wrap", layout="distinct", original_hi=0, original_lo=0xC0000000,
                     recompiled_hi=0, recompiled_lo=0, output_bytes=18, outputs_equal=True,
                     original_caller_mfhi_mflo_addresses=[],
                     scope="HI/LO differ in this VEX case. Equality is limited to checked output, memory and ABI observables; not whole-machine state or hardware behavior.")


def digest(data):
    return sha256(data).hexdigest()


def read_pinned(path, expected, *, lf=False):
    data = path.read_bytes()
    if lf:
        data = data.replace(b"\r\n", b"\n")
    if digest(data) != expected:
        raise ValueError(f"SHA-256 mismatch for {path.name}")
    return data


def require(condition, message):
    if not condition:
        raise ValueError(message)


def build(zig, work, ELFFile):
    source = read_pinned(SOURCE, SOURCE_SHA256, lf=True)
    executable = read_pinned(zig, ZIG_SHA256)
    snapshot = work / "zig-snapshot.exe"
    with snapshot.open("xb") as file:
        require(file.write(executable) == len(executable), "short compiler snapshot write")
    del executable
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(work / "cache-global"),
               ZIG_LOCAL_CACHE_DIR=str(work / "cache-local"), ZIG_LIB_DIR=str(zig.parent / "lib"))
    try:
        version = subprocess.check_output([str(snapshot), "version"], cwd=work, env=env,
                                          text=True, timeout=30).strip()
        require(version == ZIG_VERSION, "unexpected compiler version")
        subprocess.run([str(snapshot), *CC_ARGS], input=source, cwd=work, env=env,
                       check=True, timeout=120)
    finally:
        snapshot.unlink()

    obj = read_pinned(work / "q7_numeric.o", OBJECT_SHA256)
    elf = ELFFile(BytesIO(obj))
    require(elf.elfclass == 32 and elf.little_endian and elf["e_machine"] == "EM_MIPS"
            and elf["e_type"] == "ET_REL" and elf["e_flags"] == ELF_FLAGS, "unexpected MIPS ELF header")
    require(struct.unpack("<H6B4I", elf.get_section_by_name(".MIPS.abiflags").data()) == ABI_FLAGS,
            "unexpected MIPS ABI flags")
    require(elf.get_section_by_name(".comment").data().rstrip(b"\0").decode("ascii") == BUILD["llvm_build"],
            "unexpected compiler comment")
    symbols = elf.get_section_by_name(".symtab")
    require(symbols is not None and not any(s.name and s["st_shndx"] == "SHN_UNDEF" for s in symbols.iter_symbols()),
            "unexpected unresolved import")
    (symbol,) = symbols.get_symbol_by_name(FUNCTION)
    index = symbol["st_shndx"]
    section = elf.get_section(index)
    require(symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_value"] == 0
            and section.name == BUILD["text_section"] and section["sh_flags"] & 4
            and symbol["st_size"] == section["sh_size"] == RECOMPILED_SIZE
            and RECOMPILED_SIZE % 4 == 0, "unexpected executable symbol extent")
    relocations = [[s.name, elf.get_section(s["sh_info"]).name, s.num_relocations()]
                   for s in elf.iter_sections() if s["sh_type"] in ("SHT_REL", "SHT_RELA")]
    require(relocations == BUILD["elf"]["metadata_relocations"]
            and not (elf.get_section_by_name(".pdr")["sh_flags"] & 2),
            "unexpected relocation or loaded .pdr")
    code = section.data()
    require(digest(code) == TEXT_SHA256, "unexpected executable text hash")
    return code


def load_segment_offset(elf, address, size):
    matches = [s["p_offset"] + address - s["p_vaddr"] for s in elf.iter_segments()
               if s["p_type"] == "PT_LOAD" and s["p_vaddr"] <= address
               and address + size <= s["p_vaddr"] + s["p_filesz"]]
    require(len(matches) == 1, f"executable range not uniquely file-backed at {address:#x}")
    return matches[0]


def overlay(firmware, original, code, ELFFile):
    for offset in CARRIER_OFFSETS:
        require(firmware[offset:offset+7] == b"\x7fELF\x01\x01\x01"
                and struct.unpack_from("<HH", firmware, offset + 16) == (2, 8)
                and struct.unpack_from("<I", firmware, offset + 36)[0] == ELF_FLAGS
                and struct.unpack_from("<I", firmware, offset + 32)[0] == 0,
                "unexpected original MIPS carrier or section-table status")
    elf = ELFFile(BytesIO(original))
    capacity = ORIGINAL_END - ORIGINAL
    require(0 < len(code) <= capacity and len(code) % 4 == 0, "compiled code exceeds original slot")
    start = load_segment_offset(elf, ORIGINAL, capacity)
    caller = load_segment_offset(elf, CALLER, CALLER_END - CALLER)
    require(digest(original[start:start+capacity]) == LEAF_SHA256
            and digest(original[caller:caller+CALLER_END-CALLER]) == CALLER_SHA256,
            "unexpected original function hash")
    return original[:start] + code + original[start+len(code):]


def fixtures():
    rng = Random(SEED)
    mixed = [-32768, 1, 32767, 0, -3, 8192, 233, -1202, 612]
    identity = [8192, 0, 0, 0, 8192, 0, 0, 0, 8192]
    pairs = (
        ("identity-left", identity, mixed), ("identity-right", mixed, identity),
        ("zero", [0]*9, mixed),
        ("positive-wrap", [-32768]*9, [-32768]*9),
        ("negative-wrap", [32767]*9, [-32768]*9),
        ("positive-half-step", [1, 0, 0]*3, [4095, 4096, 4097]+[0]*6),
        ("negative-half-step", [-1, 0, 0]*3, [4095, 4096, 4097]+[0]*6),
        ("low-halfword-wrap", [-32768, 0, 0]*3, [-32768, 32767, 8192]+[0]*6),
    )
    for name, left, right in pairs:
        for layout in LAYOUTS:
            yield name, left, right, layout
    for i in range(32):
        left = [rng.randrange(-32768, 32768) for _ in range(9)]
        right = [rng.randrange(-32768, 32768) for _ in range(9)]
        yield f"random-{i:02}", left, right, LAYOUTS[i % len(LAYOUTS)]


def leaf_fixture(name, left, right, layout):
    alias, left_offset, right_offset, out_offset = layout
    arena = bytearray(b"\xa5" * 0x100)
    struct.pack_into("<9h", arena, left_offset, *left)
    struct.pack_into("<9h", arena, right_offset, *right)
    effective_left = struct.unpack_from("<9h", arena, left_offset)
    effective_right = struct.unpack_from("<9h", arena, right_offset)
    expected = matrix_reference(effective_left, effective_right, 13)
    result = struct.pack("<9h", *expected)
    record = dict(case=name, layout=alias, input_sha256=digest(arena), output_sha256=digest(result))
    args = (ARENA + out_offset, ARENA + left_offset, ARENA + right_offset)
    return record, arena, args, result


def scalar(state, expression):
    if isinstance(expression, int):
        return expression
    require(not expression.symbolic, "symbolic value in concrete replay")
    return state.solver.eval(expression)


def read_memory(state, address, size):
    expression = state.memory.load(address, size, inspect=False)
    require(not expression.symbolic, f"symbolic memory at {address:#x}")
    return state.solver.eval(expression, cast_to=bytes)


def run(project, angr, start, args, memory, code_bounds, write_bounds, read_bounds, *, fifth=None):
    state = project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.memory.store(STACK_BASE, b"\x79" * (STACK_TOP - STACK_BASE + 24))
    for address, data in memory.items():
        state.memory.store(address, bytes(data))
    for index, value in enumerate(args):
        setattr(state.regs, f"a{index}", value)
    if fifth is not None:
        state.memory.store(STACK_TOP + 16, struct.pack("<I", fifth))
    for i, name in enumerate(SAVED):
        setattr(state.regs, name, STACK_TOP if name == "sp" else 0x13570000 + i * 0x10203)
    abi = tuple(scalar(state, getattr(state.regs, r)) for r in SAVED)
    state.regs.pc, state.regs.ra = start, RETURN_PC
    writes, calls = [], []

    def within(ranges, address, size):
        return any(lo <= address and address + size <= hi for lo, hi in ranges)

    def on_instruction(s):
        address = scalar(s, s.inspect.attrs.instruction)
        require(within(code_bounds, address, 4), f"execution outside allowed code at {address:#x}")
        if start == CALLER and address == ORIGINAL:
            args = [scalar(s, getattr(s.regs, f"a{i}")) for i in range(3)]
            input_hash = digest(read_memory(s, args[1], 18) + read_memory(s, args[2], 18))
            calls.append([scalar(s, s.regs.ra) - 8, *args, input_hash])

    def on_read(s):
        address = scalar(s, s.inspect.attrs.mem_read_address)
        size = scalar(s, s.inspect.attrs.mem_read_length)
        require(within(read_bounds, address, size), f"read outside allowed data at {address:#x}, {size} bytes")

    def on_write(s):
        address = scalar(s, s.inspect.attrs.mem_write_address)
        size = scalar(s, s.inspect.attrs.mem_write_length)
        if within(((STACK_BASE, STACK_TOP + (16 if fifth is not None else 0)),), address, size):
            return
        require(within(write_bounds, address, size), f"write outside allowed data at {address:#x}, {size} bytes")
        writes.append([address, size, scalar(s, s.inspect.attrs.mem_write_expr)])

    state.inspect.b("instruction", when=angr.BP_BEFORE, action=on_instruction)
    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=on_read)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_write)
    sim = project.factory.simgr(state, save_unconstrained=True)
    sim.explore(find=RETURN_PC, n=5000)
    require(len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained,
            f"failed bounded replay at {start:#x}: {sim.errored}")
    final = sim.found[0]
    require(tuple(scalar(final, getattr(final.regs, r)) for r in SAVED) == abi
            and scalar(final, final.regs.ra) == RETURN_PC, "callee-preserved ABI registers changed")
    if fifth is not None:
        require(read_memory(final, STACK_TOP + 16, 4) == struct.pack("<I", fifth), "fifth argument changed")
    return final, writes, calls


def replay_leaf(projects, angr):
    records = []
    for spec in fixtures():
        record, arena, args, result = leaf_fixture(*spec)
        dest, left, right = args
        memory = {ARENA: arena}
        reads = ((left, left+18), (right, right+18), (STACK_BASE, STACK_TOP))
        expected_writes = [[dest+i, 2, word] for i, (word,) in zip(range(0, 18, 2), struct.iter_unpack("<H", result))]
        for project, end in zip(projects, (ORIGINAL_END, ORIGINAL + RECOMPILED_SIZE), strict=True):
            state, writes, _ = run(project, angr, ORIGINAL, args, memory, ((ORIGINAL, end),),
                                   ((dest, dest+18),), reads)
            want = bytearray(arena)
            want[dest-ARENA:dest-ARENA+18] = result
            require(writes == expected_writes and read_memory(state, ARENA, len(arena)) == want,
                    f"leaf result, write order or guard mismatch: {record['case']} / {record['layout']}")
        records.append(record)
    return records


def caller_sites(color_space):
    sites = [0x8041C2B4, 0x8041C2F8]
    if color_space == 1:
        sites.append(0x8041C694)
    return sites + [0x8041C480, 0x8041C498]*6


def replay_caller(projects, angr):
    records = []
    for color_space, style, hue, sat in CALLER_CASES:
        source = bytearray(0x240)
        for offset, value in ((0x34, style), (0x35, sat), (0x39, hue)):
            source[offset] = value
        struct.pack_into("<I", source, 0x178, 8192)
        struct.pack_into("<I", source, 0x1FC, color_space)
        memory = {INPUT: source, OUT2: b"\xa5"*0x80, OUT3: b"\xa5"*0x80, OUT5: b"\xa5"*0x80,
                  SCRATCH-0x20: b"\xa5"*0x60}
        reads = tuple((a, a+len(data)) for a, data in memory.items()) + (
            (STACK_BASE, STACK_TOP+20), (0x80445874, 0x804458E0),
            (0x804AD450, 0x804AE300), (0x804F0B24, 0x804F0B28))
        out_ranges = ((OUT2+0x18, OUT2+0x2C), (OUT3+0x18, OUT3+0x2E),
                      (OUT5, OUT5+108), (SCRATCH, SCRATCH+18))
        observations = []
        for project, end in zip(projects, (ORIGINAL_END, ORIGINAL+RECOMPILED_SIZE), strict=True):
            state, writes, calls = run(project, angr, CALLER, (INPUT, 0, OUT2, OUT3), memory,
                                       ((ORIGINAL, end), (HUE, CALLER_END)), out_ranges, reads, fifth=OUT5)
            require([c[0] for c in calls] == caller_sites(color_space), "unexpected original caller branch")
            require(scalar(state, state.regs.v0) == SCRATCH, "caller returned wrong scratch address")
            require(read_memory(state, INPUT, len(source)) == source, "caller altered source object")
            for address, data in memory.items():
                actual = read_memory(state, address, len(data))
                for i, byte in enumerate(actual):
                    if not any(lo <= address+i < hi for lo, hi in out_ranges):
                        require(byte == data[i], "caller changed a guard byte")
            output_bytes = b"".join(read_memory(state, a, len(memory[a])) for a in (OUT2, OUT3, OUT5, SCRATCH-0x20))
            observations.append((writes, calls, output_bytes))
        require(observations[0] == observations[1], "original caller output or call trace changed")
        writes, calls, output_bytes = observations[0]
        records.append(dict(color_space=color_space, style=style, hue=hue, saturation=sat,
                            call_sites=[c[0] for c in calls], nonstack_stores=len(writes),
                            call_inputs_sha256=digest(json.dumps(calls, separators=(",", ":")).encode("ascii")),
                            guarded_outputs_sha256=digest(output_bytes)))
    return records


def replay_machine_state(projects, angr, original, ELFFile):
    spec = next(spec for spec in fixtures() if spec[0] == "positive-wrap" and spec[3][0] == "distinct")
    _, arena, args, expected = leaf_fixture(*spec)
    dest, left, right = args
    observed = []
    for project, end in zip(projects, (ORIGINAL_END, ORIGINAL+RECOMPILED_SIZE), strict=True):
        state, _, _ = run(project, angr, ORIGINAL, args, {ARENA: arena}, ((ORIGINAL, end),),
                          ((dest, dest+18),), ((left, left+18), (right, right+18), (STACK_BASE, STACK_TOP)))
        require(read_memory(state, dest, 18) == expected, "machine-state probe output changed")
        observed.append((scalar(state, state.regs.hi), scalar(state, state.regs.lo)))
    elf = ELFFile(BytesIO(original))
    off = load_segment_offset(elf, CALLER, CALLER_END-CALLER)
    reads = [CALLER+i*4 for i, (word,) in enumerate(struct.iter_unpack("<I", original[off:off+CALLER_END-CALLER]))
             if word & 0xFC00003F in (0x10, 0x12)]
    report = dict(MACHINE_STATE, original_hi=observed[0][0], original_lo=observed[0][1],
                  recompiled_hi=observed[1][0], recompiled_lo=observed[1][1],
                  original_caller_mfhi_mflo_addresses=reads)
    require(report == MACHINE_STATE, "unexpected HI/LO observation")
    return report


def verify(firmware_path, elf_path, zig, work):
    if not __debug__:
        raise RuntimeError("Replay requires assertions")
    firmware = read_pinned(firmware_path, FIRMWARE_SHA256)
    original = read_pinned(elf_path, ELF_SHA256)
    from elftools.elf.elffile import ELFFile
    import angr

    work.mkdir(parents=True)
    code = build(zig, work, ELFFile)
    patched = overlay(firmware, original, code, ELFFile)
    projects = [angr.Project(BytesIO(image), auto_load_libs=False) for image in (original, patched)]
    leaves = replay_leaf(projects, angr)
    caller = replay_caller(projects, angr)
    report = dict(input_sha256=FIRMWARE_SHA256, analysis_elf_sha256=ELF_SHA256,
                  engine=f"angr {angr.__version__} / VEX", build=BUILD, original=ORIGINAL_INFO,
                  scope=SCOPE, leaf_cases=leaves, caller_cases=caller,
                  leaf_case_count=len(leaves), caller_case_count=len(caller),
                  substituted_calls=sum(len(c["call_sites"]) for c in caller),
                  ordered_leaf_store_count_per_image=9*len(leaves))
    report["machine_state_probe"] = replay_machine_state(projects, angr, original, ELFFile)
    validate_report(report)
    return report


def validate_report(report):
    """Validate metadata and recompute the synthetic leaf reference without binaries."""
    leaves = [leaf_fixture(*spec)[0] for spec in fixtures()]
    require(report["input_sha256"] == FIRMWARE_SHA256 and report["analysis_elf_sha256"] == ELF_SHA256
            and report["build"] == BUILD and report["original"] == ORIGINAL_INFO and report["scope"] == SCOPE
            and report["leaf_cases"] == leaves and report["leaf_case_count"] == len(leaves)
            and report["ordered_leaf_store_count_per_image"] == len(leaves)*9
            and report["caller_case_count"] == len(CALLER_CASES), "unexpected report identity or leaf reference")
    engine = report["engine"]
    require(isinstance(engine, str) and engine.startswith("angr ") and engine.endswith(" / VEX"), "invalid replay engine")
    count = 0
    for case, spec in zip(report["caller_cases"], CALLER_CASES, strict=True):
        require(tuple(case[k] for k in ("color_space", "style", "hue", "saturation")) == spec
                and case["call_sites"] == caller_sites(spec[0]) and case["nonstack_stores"] > 0,
                "unexpected original caller fixture")
        for key in ("call_inputs_sha256", "guarded_outputs_sha256"):
            require(len(case[key]) == 64 and all(ch in "0123456789abcdef" for ch in case[key]),
                    "invalid caller digest")
        count += len(case["call_sites"])
    require(report["substituted_calls"] == count, "substituted-call count mismatch")
    require(report["machine_state_probe"] == MACHINE_STATE, "machine-state scope mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    private = (ROOT / ".private" / "recompiled-numeric").resolve()
    work = args.work_dir.resolve()
    if os.path.lexists(args.output):
        parser.error("output must not exist")
    if work == private or not work.is_relative_to(private) or work.exists():
        parser.error("work-dir must be new and below .private/recompiled-numeric")
    report = verify(args.firmware, args.elf, args.zig.resolve(), work)
    with args.output.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    print(f"PASS {report['leaf_case_count']} leaf cases, {report['caller_case_count']} caller cases, "
          f"{report['substituted_calls']} substituted calls")


if __name__ == "__main__":
    main()
