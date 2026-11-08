"""Replay Q7 E01 up to its first program request and verify the program/readback helper."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
from os.path import lexists
from pathlib import Path
import struct

from inspect_q7 import parse_elf
from q7_symbols import SHA


BOOT_SHA256 = "1ea1d44c941294684683ffae9c928e985bdde8a7b68d8579b026649e5746e487"
BURN, PROGRAM, STORAGE = 0x80012654, 0x80011DA8, 0x8008249C
HANDLE, PRIMARY, OLD_HEADER, HEAP = 0x10000000, 0x10010000, 0x10007000, 0x11000000
SOURCE, READBACK, EXTRA, MAP = PRIMARY, 0x10020000, 0x10030000, 0x10040000
STACK, RETURN = 0x70008000, 0x0BADF000
CARD_OFFSET, BLOCK_SECTORS, BLOCK_COUNT, USER_START = 0x1000C0, 256, 1024, 640
SECTOR_BYTES, EXTRA_BYTES = 512, 16
CHUNK = BLOCK_SECTORS * SECTOR_BYTES
PENDING_DATA = {
    "incoming_sha256": "7e8bacdadfd57f7f2d6044d433f9a0ade5fa920a57c779a0cbdc6393366b15df",
    "program_source_sha256": "a13f08d36e17dc3bfb9deb769d3e1eab95acfb48bfa437ac734d069c72720e29",
    "changed_byte_count": 281,
}
LAYOUT = ((0, 0), (0, 0xA00), (0xA00, 0x13600), (0x14000, 0x6000),
          (0x1A000, 0x1000), (0x1B000, 0xD000), (0x28000, 0x18000))
PREFIX_HOOKS = {
    0x80034720: "allocate zeroed synthetic heap",
    0x80048CF8: "cache maintenance no-op",
    0x80034D98: "free no-op",
    0x8004717C: "diagnostic log no-op",
    0x8001A444: "header diagnostic no-op",
    0x80019014: "card callback supplies original package bytes",
    0x8008495C: "existing-media header returns synthetic installed header",
    0x80083744: "synthetic zone geometry",
    STORAGE: "operation 6 fills 16 spare bytes with FF and returns 0; operation 8 returns 0",
}
PROGRAM_HOOKS = {
    0x8004717C: "diagnostic log no-op",
    STORAGE: "operation 5 returns fixture status; operation 4 supplies synthetic readback and fixture status",
}
USER_RANGE = 0x800117D0
USER_RANGE_CASES = (
    (1, 384, 639), (1, 384, 640), (1, 384, 1023), (1, 384, 1024),
    (0, 384, 640), (2, 384, 640), (1, 0, 640),
)
PROGRAM_CASES = (
    ("equal-one", 1, 0, 0, None, True),
    ("equal-two", 2, 0, 0, None, True),
    ("write-fail", 2, 7, 0, None, True),
    ("read-fail", 2, 0, 7, None, True),
    ("mismatch-first", 2, 0, 0, 0, True),
    ("mismatch-middle", 2, 0, 0, 511, True),
    ("mismatch-last", 2, 0, 0, 1023, True),
    ("mismatch-no-map", 1, 0, 0, 511, False),
)


def reference_schedule():
    for block in range(USER_START):
        sector = block * BLOCK_SECTORS
        yield (6, sector, 1)
        yield (6, sector + 1, 1)
        yield (6, sector, 1)
        yield (8, block, 1)
    for block in range(USER_START, BLOCK_COUNT):
        sector = block * BLOCK_SECTORS
        yield (6, sector, 1)
        yield (6, sector + 1, 1)
    yield from ((6, 0, 1), (6, 1, 1), (6, 0, 1))


def schedule_report(schedule):
    erases = [location for op, location, _ in schedule if op == 8]
    return dict(total_modeled_requests=len(schedule), operation_6=sum(op == 6 for op, _, _ in schedule),
                operation_8=len(erases), operation_8_block_range=[min(erases), max(erases)],
                encoding="ordered little-endian u32 triples (operation, location, count)",
                sha256=sha256(b"".join(struct.pack("<3I", *event) for event in schedule)).hexdigest())


def request(ra, args):
    return dict(return_address=hex(ra), arguments=[hex(value) for value in args])


def reference_prefix():
    return dict(entry=hex(BURN), stop_before=hex(STORAGE), synthetic_blocks=BLOCK_COUNT,
                sectors_per_block=BLOCK_SECTORS, sector_bytes=SECTOR_BYTES,
                handle_protect=1,
                installed_header=dict(header_mode=1, user_start_block=USER_START,
                                      user_block_count=BLOCK_COUNT-USER_START, layout=[list(pair) for pair in LAYOUT]),
                card_reads=[dict(original_file_offset=hex(CARD_OFFSET), byte_count=CHUNK)],
                card_offset_after=hex(CARD_OFFSET+CHUNK),
                existing_header_selectors=[0, 1], allocation_sizes=[1025, 1536],
                schedule=schedule_report(list(reference_schedule())),
                first_operation_6=request(0x800117C0, (HANDLE, 6, 0, 1, 0, 0x70007930, EXTRA_BYTES)),
                first_operation_8=request(0x80013478, (HANDLE, 8, 0, 1, 0, 0, 0)),
                first_operation_5=request(0x80011E10, (HANDLE, 5, 0, BLOCK_SECTORS, PRIMARY, 0x70007A98, EXTRA_BYTES)))


def program_reference():
    rows = []
    for name, sectors, wr, rd, mismatch, has_map in PROGRAM_CASES:
        success = wr == rd == 0 and mismatch is None
        calls = [dict(operation=5, sector=3*sectors, count=sectors, status=wr)]
        if wr == 0:
            calls.append(dict(operation=4, sector=3*sectors, count=sectors, status=rd))
        compared = 0 if wr or rd else (sectors*SECTOR_BYTES if mismatch is None else mismatch+1)
        rows.append(dict(name=name, sectors=sectors, block=3, map_present=has_map, mismatch_byte=mismatch,
                         result=int(success), map="___x_____" if not success and has_map else "_________",
                         compared_bytes_per_operand=compared, events=calls))
    return rows


def num(state, value):
    if isinstance(value, int):
        return value
    assert not value.symbolic, value
    return state.solver.eval(value)


def u32(state, address):
    return num(state, state.memory.load(address, 4, endness="Iend_LE", inspect=False))


def read_bytes(state, address, size):
    value = state.memory.load(address, size, inspect=False)
    assert not value.symbolic
    return state.solver.eval(value, cast_to=bytes)


def put_u32(state, address, value):
    state.memory.store(address, struct.pack("<I", value), inspect=False)


def arguments(state):
    sp = num(state, state.regs.sp)
    return [num(state, getattr(state.regs, f"a{i}")) for i in range(4)] + [
        u32(state, sp + offset) for offset in (16, 20, 24)]


def base_state(project, angr, address, args, *, stack_size=0x1000, handle_size=0x2000):
    state = project.factory.blank_state(addr=address, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp, state.regs.ra = STACK, RETURN
    for i, value in enumerate(args):
        setattr(state.regs, f"a{i}", value)
    state.memory.store(STACK - stack_size, bytes(stack_size + 0x1000))
    state.memory.store(HANDLE, bytes(handle_size))
    return state


def replay_prefix(project, angr, firmware, *, observe=None):
    card_reads, selectors, allocations, schedule, first = [], [], [], [], {}
    position, heap = CARD_OFFSET, HEAP

    class Model(angr.SimProcedure):
        def run(self, a0, a1, a2, a3, kind=None):
            nonlocal position, heap
            st = self.state
            if kind == "alloc":
                size = num(st, a1)
                assert 0 < size <= 0x100000
                address = heap
                heap += (size + 15) & ~15
                st.memory.store(address, bytes(size))
                allocations.append(size)
                return address
            if kind == "payload":
                size, address = num(st, a0), num(st, a1)
                assert (size, address) == (CHUNK, PRIMARY) and position+size <= len(firmware)-32
                st.memory.store(address, firmware[position:position+size])
                card_reads.append(dict(original_file_offset=hex(position), byte_count=size))
                position += size
                return 1
            if kind == "header":
                selectors.append(num(st, a3))
                return OLD_HEADER
            if kind == "zones":
                put_u32(st, num(st, a2), BLOCK_COUNT*BLOCK_SECTORS)
                put_u32(st, num(st, a3), 1)
                for offset in (16, 20):
                    put_u32(st, u32(st, num(st, st.regs.sp)+offset), BLOCK_SECTORS)
                return 0
            if kind == "storage":
                args = arguments(st)
                handle, operation, location, count, data, extra, size = args
                assert handle == HANDLE and operation in (6, 8) and count == 1 and data == 0
                first.setdefault(operation, request(num(st, st.regs.ra), args))
                if operation == 6:
                    assert size == EXTRA_BYTES
                    st.memory.store(extra, b"\xff"*size)
                else:
                    assert extra == size == 0
                schedule.append((operation, location, count))
            return 0

    kinds = {0x80034720: "alloc", 0x80019014: "payload", 0x8008495C: "header",
             0x80083744: "zones", STORAGE: "storage"}
    for address in PREFIX_HOOKS:
        project.hook(address, Model(kind=kinds.get(address)))
    st = base_state(project, angr, BURN, (HANDLE, 0x800A74DC), stack_size=0x2000, handle_size=0x9000)
    existing = bytearray(firmware[CARD_OFFSET:CARD_OFFSET+0x800])
    for kind, (start, span) in enumerate(LAYOUT):
        offset = 0x3B0 if kind == 0 else 0x214 + kind*0x24
        struct.pack_into("<9I", existing, offset, start, span, 0, 0, 0, 0, 0, 0, 0)
    struct.pack_into("<II", existing, 0x310, USER_START, BLOCK_COUNT-USER_START)
    assert existing[0x234] == 1
    st.memory.store(OLD_HEADER, bytes(existing))
    put_u32(st, 0x800A7770, HANDLE)
    for offset, value in ((0x138, SECTOR_BYTES), (0x1238, BLOCK_SECTORS),
                          (0x123C, BLOCK_COUNT*BLOCK_SECTORS), (0x1248, CHUNK),
                          (0x124C, PRIMARY), (0x126C, 1)):
        put_u32(st, HANDLE+offset, value)
    st.memory.store(HANDLE+0x1268, b"\x01")
    if observe is not None:
        observe(st)
    sim = project.factory.simgr(st, save_unconstrained=True)
    sim.explore(find=lambda s: s.addr == STORAGE and num(s, s.regs.a1) not in (6, 8), avoid=RETURN, n=150000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.avoid and not sim.unconstrained, sim
    final = sim.found[0]
    assert schedule == list(reference_schedule())
    result = dict(reference_prefix(), card_reads=card_reads, card_offset_after=hex(position),
                  existing_header_selectors=selectors, allocation_sizes=allocations, schedule=schedule_report(schedule),
                  first_operation_6=first[6], first_operation_8=first[8],
                  first_operation_5=request(num(final, final.regs.ra), arguments(final)))
    assert result == reference_prefix()
    original_chunk = firmware[CARD_OFFSET:CARD_OFFSET+CHUNK]
    pending_chunk = read_bytes(final, PRIMARY, CHUNK)
    result["pending_data"] = dict(incoming_sha256=sha256(original_chunk).hexdigest(),
                                  program_source_sha256=sha256(pending_chunk).hexdigest(),
                                  changed_byte_count=sum(a != b for a, b in zip(original_chunk, pending_chunk, strict=True)))
    return result


def replay_program(project, angr):
    class Storage(angr.SimProcedure):
        def run(self, a0, a1, a2, a3):
            st = self.state
            handle, operation, sector, count, buffer, extra, size = arguments(st)
            sectors, wr, rd, mismatch, content = st.globals["fixture"]
            assert (handle, sector, count) == (HANDLE, 3*sectors, sectors)
            if operation == 5:
                assert (buffer, extra, size) == (SOURCE, EXTRA, EXTRA_BYTES)
                assert read_bytes(st, SOURCE, len(content)) == content
                assert read_bytes(st, EXTRA, EXTRA_BYTES) == b"\xff"*EXTRA_BYTES
                status = wr
            else:
                assert operation == 4 and (buffer, extra, size) == (READBACK, 0, 0)
                data = bytearray(content)
                if mismatch is not None:
                    data[mismatch] ^= 0xff
                if rd == 0:
                    st.memory.store(buffer, bytes(data), inspect=False)
                status = rd
            event = dict(operation=operation, sector=sector, count=count, status=status)
            st.globals["events"] = (*st.globals["events"], event)
            return status

    class Log(angr.SimProcedure):
        def run(self):
            return 0

    project.hook(STORAGE, Storage(), replace=True)
    project.hook(0x8004717C, Log(), replace=True)
    rows = []
    for spec, expected in zip(PROGRAM_CASES, program_reference(), strict=True):
        name, sectors, wr, rd, mismatch, has_map = spec
        content = bytes((i*17+3) % 256 for i in range(sectors*SECTOR_BYTES))
        st = base_state(project, angr, PROGRAM, (HANDLE, 3, SOURCE, EXTRA))
        put_u32(st, HANDLE+0x1238, sectors)
        put_u32(st, HANDLE+0x1250, READBACK)
        put_u32(st, STACK+16, MAP if has_map else 0)
        source = b"\xa5"*8 + content + b"\xa5"*8
        st.memory.store(SOURCE-8, source)
        st.memory.store(READBACK-8, b"\x5a"*(len(content)+16))
        st.memory.store(EXTRA, b"\xff"*EXTRA_BYTES)
        st.memory.store(MAP, b"_"*9)
        st.globals["fixture"] = (sectors, wr, rd, mismatch, content)
        st.globals["events"] = ()
        reads = [0, 0]

        def compare_read(s):
            address = num(s, s.inspect.attrs.mem_read_address)
            if SOURCE <= address < SOURCE+len(content):
                index, base = 0, SOURCE
            elif READBACK <= address < READBACK+len(content):
                index, base = 1, READBACK
            else:
                return
            assert num(s, s.inspect.attrs.mem_read_length) == 1 and address == base + reads[index]
            reads[index] += 1

        st.inspect.b("mem_read", when=angr.BP_BEFORE, action=compare_read)
        sim = project.factory.simgr(st, save_unconstrained=True)
        sim.explore(find=RETURN, n=6000)
        assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, (name, sim.errored)
        final = sim.found[0]
        assert num(final, final.regs.sp) == STACK
        assert read_bytes(final, SOURCE-8, len(source)) == source
        assert read_bytes(final, EXTRA, EXTRA_BYTES) == b"\xff"*EXTRA_BYTES
        assert read_bytes(final, READBACK-8, 8) == read_bytes(final, READBACK+len(content), 8) == b"\x5a"*8
        assert reads[0] == reads[1]
        row = dict(expected, result=num(final, final.regs.v0), map=read_bytes(final, MAP, 9).decode("ascii"),
                   compared_bytes_per_operand=reads[0], events=list(final.globals["events"]))
        assert row == expected, (row, expected)
        rows.append(row)
    return rows


def user_range_reference():
    return [dict(header_mode=mode, start=USER_START, count=count, block=block,
                 result=int(mode != 0 and count != 0 and USER_START <= block < USER_START + count))
            for mode, count, block in USER_RANGE_CASES]


def replay_user_range(project, angr):
    rows = []
    for expected in user_range_reference():
        st = base_state(project, angr, USER_RANGE, (OLD_HEADER, expected["block"]))
        st.memory.store(OLD_HEADER, bytes(0x400))
        st.memory.store(OLD_HEADER+0x234, bytes([expected["header_mode"]]))
        put_u32(st, OLD_HEADER+0x310, expected["start"])
        put_u32(st, OLD_HEADER+0x314, expected["count"])
        sim = project.factory.simgr(st, save_unconstrained=True)
        sim.explore(find=RETURN, n=100)
        assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, sim
        final = sim.found[0]
        assert num(final, final.regs.sp) == STACK
        row = dict(expected, result=num(final, final.regs.v0))
        assert row == expected
        rows.append(row)
    return rows


def modeled(hooks):
    return {hex(address): description for address, description in hooks.items()}


def validate_report(report):
    """Validate deterministic replay metadata using only the standard library."""
    if not __debug__:
        raise RuntimeError("Validation requires assertions")
    assert report["input_sha256"] == SHA and report["boot_elf_sha256"] == BOOT_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["modeled_prefix"] == modeled(PREFIX_HOOKS)
    assert report["modeled_program"] == modeled(PROGRAM_HOOKS)
    prefix = dict(report["preflight"])
    data = prefix.pop("pending_data")
    assert prefix == reference_prefix()
    assert data == PENDING_DATA
    assert report["program_cases"] == program_reference()
    assert report["user_range_cases"] == user_range_reference()


def replay(firmware):
    if not __debug__:
        raise RuntimeError("Replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    boot, _ = parse_elf(firmware, 0x200)
    if boot["sha256_referenced_bytes"] != BOOT_SHA256:
        raise ValueError("unexpected E01 boot ELF extent")
    import angr

    project = angr.Project(BytesIO(firmware[0x200:boot["referenced_end"]]), auto_load_libs=False)
    preflight = replay_prefix(project, angr, firmware)
    programs = replay_program(project, angr)
    report = dict(input_sha256=SHA, boot_elf_sha256=BOOT_SHA256, engine=f"angr {angr.__version__} / VEX",
                  preflight=preflight, program_cases=programs, user_range_cases=replay_user_range(project, angr),
                  modeled_prefix=modeled(PREFIX_HOOKS), modeled_program=modeled(PROGRAM_HOOKS))
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error("replay requires assertions")
    if lexists(args.output):
        parser.error("output must not exist")
    report = replay(args.firmware.read_bytes())
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"PASS {report['preflight']['schedule']['total_modeled_requests']} modeled preflight requests and "
          f"{len(report['program_cases'])} program/readback cases, "
          f"{len(report['user_range_cases'])} user-range cases")


if __name__ == "__main__":
    main()
