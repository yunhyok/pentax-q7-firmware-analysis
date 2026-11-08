"""Replay Q7 BurnNand continuation from a verified first-program snapshot."""
import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
from os.path import lexists
from pathlib import Path

import check_burn_storage as storage
from inspect_q7 import parse_elf
from q7_symbols import SHA


CARD_READ = 0x80019014
ALLOC = 0x80034720
MAIN_PROGRAM_RETURN = 0x80013AB0
MARK_RETURN = 0x80013B90
PROTECT_RETURN = 0x80013694
EXHAUSTED = 0x80014890
CARD_FAILURE = 0x8001374C
METADATA_PROGRAM_RETURN = 0x8001437C
MARK_SPARE = b"\xff"*4 + b"\0\xf0" + b"\xff"*10
BAD_SPARE = b"\xff"*5 + b"\0" + b"\xff"*10
PREFIX_MODEL = storage.modeled(storage.PREFIX_HOOKS)
CONTINUATION_MODEL = {
    **storage.modeled({
        address: storage.PREFIX_HOOKS[address]
        for address in (0x80048CF8, 0x80034D98, 0x8004717C)
    }),
    hex(ALLOC): "zeroed synthetic heap, continuing the prefix allocation cursor",
    hex(CARD_READ): "read the next complete original package chunk or return fixture failure without advancing",
    hex(storage.STORAGE): "op 6 supplies synthetic spare bytes; op 7 returns fixture status and retains successful spare writes",
    hex(storage.PROGRAM): "aggregate result 1 on success or 0 plus x in the map on failure; no device or readback execution",
}


@dataclass(frozen=True)
class Fixture:
    name: str
    stop_after: int | None = None
    fail_first_program: bool = False
    op7_status: int = 0
    card_status: int = 1
    bad_blocks: range = range(0)


FIXTURES = (
    Fixture("nominal-prefix", stop_after=3),
    Fixture("program-retry", stop_after=3, fail_first_program=True),
    Fixture("marker-error-retry", stop_after=2, fail_first_program=True, op7_status=7),
    Fixture("spare-bad-block", stop_after=2, bad_blocks=range(1, 2)),
    Fixture("next-card-read-error", card_status=0),
    Fixture("candidate-exhaustion", fail_first_program=True, bad_blocks=range(1, storage.USER_START)),
    Fixture("main-payload-to-metadata"),
)


# Canonical summaries from the independently checked ordered traces.
CASE_SHA256 = (
    ("nominal-prefix", "4c6da89e7a84abe342bd13368f2fb99a99a167fa61bbf30a0eeb66103d38c163"),
    ("program-retry", "55a496adde79646f74040da1a97f704cfae0be83f4594b3ce20f403d3ae592c9"),
    ("marker-error-retry", "e6781fc366f5718c3746ee6f0a16edbc68bd33619ad57c317f71743e75984f78"),
    ("spare-bad-block", "77c3e50c26b0e47e0606add9f1bff8b4cc908eaac1df3db2b5db6da9fd096746"),
    ("next-card-read-error", "ebf8efe83488df7bb705defd87794a79b0c2f2d4140c5f51a5c0f5f4b8359f86"),
    ("candidate-exhaustion", "c2d970ccca1d6cd9d9ff7bf965902f677856f996f485f76852bbb9d2606e0487"),
    ("main-payload-to-metadata", "96e74ccdb8c6eae3a53a5e361def8c8ab58dc0e0d3f3d2b2bd42495082378f9d"),
)


def digest(value):
    return sha256(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")).hexdigest()


def capture_prefix(project, angr, firmware):
    saved = []

    def install(st):
        def capture(state):
            assert not saved and state.inspect.instruction == storage.PROGRAM
            assert state.addr == storage.PROGRAM
            snap = state.copy()
            snap.inspect.remove_breakpoint("instruction", bp=breakpoint)
            saved.append(snap)

        breakpoint = st.inspect.b("instruction", when=angr.BP_BEFORE,
                                  instruction=storage.PROGRAM, action=capture)

    prefix = storage.replay_prefix(project, angr, firmware, observe=install)
    assert len(saved) == 1 and prefix == dict(storage.reference_prefix(), pending_data=storage.PENDING_DATA)
    snap = saved[0]
    assert storage.arguments(snap)[:5] == [
        storage.HANDLE, 0, storage.PRIMARY, 0x70007A98, storage.HEAP,
    ]
    assert storage.num(snap, snap.regs.ra) == MAIN_PROGRAM_RETURN
    assert storage.u32(snap, storage.num(snap, snap.regs.sp)+0x564) == storage.BLOCK_COUNT
    assert storage.read_bytes(snap, storage.HEAP, storage.BLOCK_COUNT) == (
        b"_"*storage.USER_START + b"P"*(storage.BLOCK_COUNT-storage.USER_START)
    )
    # These prefix-only operations would require a separately defined continuation fixture.
    for address in (0x8001A444, 0x8008495C, 0x80083744):
        project.unhook(address)
    return snap, prefix


def run_case(project, angr, firmware, snapshot, prefix, fixture):
    programs, card_reads, io_calls, markers, terminal_sites = [], [], [], [], []
    protected, spare_writes = [], {}
    next_offset = int(prefix["card_offset_after"], 16)
    heap = storage.HEAP + sum((size+15) & ~15 for size in prefix["allocation_sizes"])

    def program_request(st):
        handle, block, data, extra, block_map = storage.arguments(st)[:5]
        sp = storage.num(st, st.regs.sp)
        ra = storage.num(st, st.regs.ra)
        assert (handle, data, extra, block_map, ra) == (
            storage.HANDLE, storage.PRIMARY, sp+0x128, storage.HEAP, MAIN_PROGRAM_RETURN,
        )
        assert 0 <= block < storage.USER_START
        data_bytes = storage.read_bytes(st, data, storage.CHUNK)
        package_bytes = firmware[next_offset-storage.CHUNK:next_offset]
        assert len(package_bytes) == storage.CHUNK
        changed = 0 if data_bytes == package_bytes else sum(
            a != b for a, b in zip(data_bytes, package_bytes, strict=True))
        return dict(block=block, logical_block=storage.num(st, st.regs.fp),
                    blocks_left_in_slice=storage.num(st, st.regs.s7), section=storage.u32(st, sp+0x660),
                    slice_byte_offset=storage.u32(st, sp+0x600), next_card_offset=hex(next_offset),
                    source_sha256=sha256(data_bytes).hexdigest(), source_changed_bytes=changed,
                    spare_sha256=sha256(storage.read_bytes(st, extra, storage.EXTRA_BYTES)).hexdigest())

    class Model(angr.SimProcedure):
        def run(self, *, kind):
            nonlocal next_offset, heap
            st = self.state
            args = storage.arguments(st)
            ra = storage.num(st, st.regs.ra)
            if kind == "program":
                row = program_request(st)
                addr = args[4]+row["block"]
                before = storage.read_bytes(st, addr, 1)
                result = int(not (fixture.fail_first_program and row["block"] == 0))
                if not result:
                    st.memory.store(addr, b"x")
                programs.append(dict(row, aggregate_result=result, map_before=before.decode("ascii"),
                                     map_after=storage.read_bytes(st, addr, 1).decode("ascii")))
                return result
            if kind == "card":
                size, dest = args[:2]
                assert (size, dest, ra) == (storage.CHUNK, storage.PRIMARY, 0x80013744)
                assert next_offset+size <= len(firmware)-32
                card_reads.append([next_offset, size, fixture.card_status, ra])
                if fixture.card_status == 1:
                    st.memory.store(dest, firmware[next_offset:next_offset+size])
                    next_offset += size
                return fixture.card_status
            if kind == "alloc":
                size = args[1]
                assert 0 < size <= 0x100000
                address = heap
                heap += (size+15) & ~15
                st.memory.store(address, bytes(size))
                return address
            handle, op, sector, count, data, extra, size = args
            assert handle == storage.HANDLE and op in (6, 7)
            assert 0 <= sector < storage.BLOCK_COUNT*storage.BLOCK_SECTORS
            assert count == 1 and data == 0 and size == storage.EXTRA_BYTES
            io_calls.append([op, sector, count, ra])
            if op == 6:
                assert ra in (0x800117C0, 0x80013FD8)
                block = sector//storage.BLOCK_SECTORS
                spare = BAD_SPARE if block in fixture.bad_blocks else spare_writes.get(sector, b"\xff"*size)
                st.memory.store(extra, spare)
                return 0
            assert sector//storage.BLOCK_SECTORS < storage.USER_START and ra == 0x80011BBC
            spare = storage.read_bytes(st, extra, size)
            assert spare == MARK_SPARE
            markers.append(dict(sector=sector, spare_status_bytes=list(spare[4:6]), status=fixture.op7_status))
            if fixture.op7_status == 0:
                spare_writes[sector] = spare
            return fixture.op7_status

    def observe(st):
        pc = st.inspect.instruction
        result = storage.num(st, st.regs.v0)
        block = storage.num(st, st.regs.s4)
        if pc == MARK_RETURN:
            terminal_sites.append(dict(site=hex(pc), block=block, marker_result=result))
        elif pc == PROTECT_RETURN:
            if result == 1:
                protected.append(block)
        else:
            terminal_sites.append(dict(site=hex(pc), block=block))

    def stop(st):
        if st.addr == storage.RETURN:
            return True
        if st.addr == storage.STORAGE:
            return storage.num(st, st.regs.a1) not in (6, 7)
        return st.addr == storage.PROGRAM and len(programs) == fixture.stop_after

    for address, kind in ((storage.PROGRAM, "program"), (storage.STORAGE, "storage"),
                          (CARD_READ, "card"), (ALLOC, "alloc")):
        project.hook(address, Model(num_args=0, kind=kind), replace=True)
    st = snapshot.copy()
    for site in (MARK_RETURN, PROTECT_RETURN, EXHAUSTED, CARD_FAILURE):
        st.inspect.b("instruction", when=angr.BP_BEFORE, instruction=site, action=observe)
    sim = project.factory.simgr(st, save_unconstrained=True)
    sim.explore(find=stop, n=70000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, sim
    final = sim.found[0]
    block_map = storage.read_bytes(final, storage.HEAP, storage.BLOCK_COUNT)
    row = dict(name=fixture.name, start=hex(snapshot.addr), stop=hex(final.addr),
               modeled_card_reads=len(card_reads), card_reads_sha256=digest(card_reads),
               last_card_read=card_reads[-1] if card_reads else None, next_card_offset=hex(next_offset),
               aggregate_program_calls=len(programs), aggregate_program_sha256=digest(programs),
               program_samples=programs if len(programs) <= 4 else [*programs[:3], programs[-1]],
               program_sections=dict(sorted(Counter(str(p["section"]) for p in programs).items())),
               io_counts=dict(sorted(Counter(str(op) for op, _, _, _ in io_calls).items())),
               io_order_sha256=digest(io_calls), markers=markers, control_sites=terminal_sites,
               source_changes=[[p["block"], p["source_changed_bytes"]] for p in programs if p["source_changed_bytes"]],
               protection_skip_count=len(protected),
               protected_skips_sha256=digest(protected),
               map_counts=dict(sorted(Counter(block_map.decode("ascii")).items())), map_first_four=block_map[:4].decode("ascii"),
               return_value=storage.num(final, final.regs.v0) if final.addr == storage.RETURN else None)
    if final.addr == storage.PROGRAM:
        row["pending_program"] = program_request(final)
    if final.addr == storage.STORAGE:
        args = storage.arguments(final)
        ra = storage.num(final, final.regs.ra)
        assert args == [storage.HANDLE, 5, 0xA00, 4, 0x11000C10, 0, 0] and ra == METADATA_PROGRAM_RETURN
        row["pending_storage"] = storage.request(ra, args)
        row["pending_storage_data_sha256"] = sha256(storage.read_bytes(
            final, args[4], args[3]*storage.SECTOR_BYTES)).hexdigest()
    return row


def validate_report(report):
    """Validate expected replay summaries without loading angr or a firmware file."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert report["input_sha256"] == SHA and report["boot_elf_sha256"] == storage.BOOT_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["modeled_prefix"] == PREFIX_MODEL
    assert report["modeled_continuation"] == CONTINUATION_MODEL
    assert report["prefix"] == dict(storage.reference_prefix(), pending_data=storage.PENDING_DATA)
    assert tuple((row["name"], digest(row)) for row in report["cases"]) == CASE_SHA256


def replay(firmware):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    boot, _ = parse_elf(firmware, 0x200)
    if boot["sha256_referenced_bytes"] != storage.BOOT_SHA256:
        raise ValueError("unexpected E01 boot ELF extent")
    import angr

    project = angr.Project(BytesIO(firmware[0x200:boot["referenced_end"]]), auto_load_libs=False)
    snapshot, prefix = capture_prefix(project, angr, firmware)
    cases = [run_case(project, angr, firmware, snapshot, prefix, fixture) for fixture in FIXTURES]
    report = dict(input_sha256=SHA, boot_elf_sha256=storage.BOOT_SHA256, engine=f"angr {angr.__version__} / VEX",
                  modeled_prefix=PREFIX_MODEL, modeled_continuation=CONTINUATION_MODEL, prefix=prefix, cases=cases)
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
    print(f"PASS {len(report['cases'])} BurnNand continuation fixtures")


if __name__ == "__main__":
    main()
