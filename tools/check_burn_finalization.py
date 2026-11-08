"""Replay Q7 BurnNand finalization with original caller code and modeled storage."""
import argparse
from hashlib import sha256
from io import BytesIO
import json
import struct
from os.path import lexists
from pathlib import Path

import check_burn_continuation as continuation
import check_burn_storage as storage
from inspect_q7 import parse_elf
from q7_symbols import SHA


EXTENDED_WRITE, PRIMARY_READ, PRIMARY_ERASE, PRIMARY_WRITE = 0x8001437C, 0x80012DF0, 0x80012F00, 0x8001465C
READY, READY_RETURN = 0x80019390, 0x80014D80
EXIT = 0x80012924
ALLOC, FREE = continuation.ALLOC, 0x80034D98
EXT_DATA, PRIMARY_DATA, EXTRA = 0x11000C10, 0x11001410, 0x70007A98
EXT_SHA256 = "a56bc5e32de831dfb0f97dfbac994227bad1045f601a806b54eb6648a8767eac"
START_CHECKPOINT = continuation.CASE_SHA256[-1]
SOURCE_HASHES = {
    "primary_aggregate_sha256": storage.PENDING_DATA["program_source_sha256"],
    "primary_aggregate_spare_sha256": "04a5c4ffa6cf440d51deeaf0b93415ce1d4165b7364e9165db149ca89d8331a2",
    "pending_extended_write_sha256": EXT_SHA256,
}
CASE_SHA256 = (
    "e8eedaaebf984b40b59fe86be2456360879836248ef6a2cb3c373ba8092f57e8",
    "c524dcfa75df619181792deaa91360219c698911ddbf43ecde007712f2bc855d",
    "673ba4ce4a28d2d440fbd4bb28aed37ecfe17cc3e9f6f33dc11bbf40d98b9f31",
    "683c1307c711cb3008269f65423d3d5ec63ee9fa113bad4bb7e68dc6465e3e3d",
)
FINALIZATION_MODEL = {
    hex(ALLOC): "Provide one zero-initialized synthetic block buffer.",
    hex(FREE): "Record the requested free arguments and return without changing synthetic RAM.",
    "0x8004717c": "Diagnostic logging no-op carried from the original preflight replay.",
    "0x80048cf8": "Cache-maintenance no-op carried from the original preflight replay.",
    hex(storage.STORAGE): (
        "Return fixture status for the four recognized requests. The block-zero read supplies the full data and "
        "spare bytes captured before its earlier aggregate program. No device I/O occurs."
    ),
}
CASES = (
    ("extended-write-error", EXTENDED_WRITE),
    ("primary-read-error", PRIMARY_READ),
    ("primary-write-error", PRIMARY_WRITE),
    ("all-success", None),
)
REQUESTS = {
    EXTENDED_WRITE: (5, 0xA00, 4, EXT_DATA, 0, 0),
    PRIMARY_READ: (4, 0, storage.BLOCK_SECTORS, PRIMARY_DATA, EXTRA, storage.EXTRA_BYTES),
    PRIMARY_ERASE: (8, 0, 1, 0, 0, 0),
    PRIMARY_WRITE: (5, 0, storage.BLOCK_SECTORS, PRIMARY_DATA, EXTRA, storage.EXTRA_BYTES),
}


def start_state(project, angr, firmware):
    initial, prefix = continuation.capture_prefix(project, angr, firmware)
    handle, block, data, extra, block_map = storage.arguments(initial)[:5]
    assert (handle, block, data, block_map) == (storage.HANDLE, 0, storage.PRIMARY, storage.HEAP)
    primary = storage.read_bytes(initial, data, storage.CHUNK)
    spare = storage.read_bytes(initial, extra, storage.EXTRA_BYTES)
    assert sha256(primary).hexdigest() == storage.PENDING_DATA["program_source_sha256"]
    captured = []
    row = continuation.run_case(project, angr, firmware, initial, prefix, continuation.FIXTURES[-1],
                                observe_final=captured.append)
    assert (row["name"], continuation.digest(row)) == START_CHECKPOINT
    assert row["pending_storage_data_sha256"] == EXT_SHA256
    snapshot, = captured
    assert snapshot.addr == storage.STORAGE
    return snapshot, primary, spare


def run_case(project, angr, snapshot, primary, spare, name, fail_at):
    requests, allocations, frees, branches = [], [], [], []
    ready_calls = []

    class Model(angr.SimProcedure):
        def run(self, *, kind):
            st = self.state
            args = storage.arguments(st)
            ra = storage.num(st, st.regs.ra)
            if kind == "alloc":
                assert ra == 0x80012DC4 and args[1] == storage.CHUNK and not allocations
                st.memory.store(PRIMARY_DATA, bytes(storage.CHUNK))
                allocations.append(dict(storage.request(ra, args[:5]), returned=hex(PRIMARY_DATA)))
                return PRIMARY_DATA
            if kind == "free":
                frees.append(storage.request(ra, args[:4]))
                return 0

            assert args == [storage.HANDLE, *REQUESTS[ra]]
            status = 7 if ra == fail_at else 0
            event = dict(storage.request(ra, args), status=status)
            requests.append(event)
            if ra == PRIMARY_READ and status == 0:
                st.memory.store(PRIMARY_DATA, primary)
                st.memory.store(EXTRA, spare)
                event.update(data_sha256=sha256(primary).hexdigest(), spare_sha256=sha256(spare).hexdigest())
            if ra in (EXTENDED_WRITE, PRIMARY_WRITE):
                data = storage.read_bytes(st, args[4], args[3]*storage.SECTOR_BYTES)
                event["data_sha256"] = sha256(data).hexdigest()
                if ra == EXTENDED_WRITE:
                    assert event["data_sha256"] == EXT_SHA256
                else:
                    expected = bytearray(primary)
                    struct.pack_into('<I', expected, 0x39C, 10)
                    assert data == expected
                    written_spare = storage.read_bytes(st, EXTRA, storage.EXTRA_BYTES)
                    assert written_spare == spare
                    event["spare_sha256"] = sha256(written_spare).hexdigest()
                    event["data_changes_from_aggregate_block_zero"] = [
                        [i, before, after] for i, (before, after) in enumerate(zip(primary, data, strict=True))
                        if before != after
                    ]
            return status

    def observe(st):
        pc = st.inspect.attrs.instruction
        if pc == READY:
            ready_calls.append(hex(storage.num(st, st.regs.ra)))
        else:
            branches.append([hex(pc), storage.num(st, st.regs.v0)])

    def stop(st):
        if st.addr in (storage.RETURN, storage.PROGRAM, continuation.CARD_READ):
            return True
        return st.addr == storage.STORAGE and storage.num(st, st.regs.ra) not in REQUESTS

    for pc, kind in ((storage.STORAGE, "storage"), (ALLOC, "alloc"), (FREE, "free")):
        project.hook(pc, Model(num_args=0, kind=kind), replace=True)
    st = snapshot.copy()
    for site in (*REQUESTS, READY, READY_RETURN, EXIT):
        st.inspect.b("instruction", when=angr.BP_BEFORE, instruction=site, action=observe)
    sim = project.factory.simgr(st, save_unconstrained=True)
    sim.explore(find=stop, n=5000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.deadended and not sim.unconstrained, sim
    final = sim.found[0]
    assert final.addr == storage.RETURN, hex(final.addr)
    assert storage.num(final, final.regs.sp) == storage.STACK
    return dict(name=name, injected_error_return_site=hex(fail_at) if fail_at is not None else None,
                entry=hex(snapshot.addr), stop=hex(final.addr), return_value=storage.num(final, final.regs.v0),
                requests=requests, allocations=allocations, free_calls=frees,
                native_ready_callers=ready_calls, native_status_sites=branches)


def validate_report(report):
    """Check the pinned model, source hashes, statuses and terminal case traces using only stdlib."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert report["input_sha256"] == SHA and report["boot_elf_sha256"] == storage.BOOT_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["main_case"] == list(START_CHECKPOINT)
    assert report["modeled_finalization"] == FINALIZATION_MODEL
    assert report["source_hashes"] == SOURCE_HASHES
    assert tuple(continuation.digest(case) for case in report["cases"]) == CASE_SHA256


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
    snapshot, primary, spare = start_state(project, angr, firmware)
    cases = [run_case(project, angr, snapshot, primary, spare, name, failure) for name, failure in CASES]
    report = dict(input_sha256=SHA, boot_elf_sha256=storage.BOOT_SHA256, engine=f"angr {angr.__version__} / VEX",
                  main_case=list(START_CHECKPOINT), modeled_finalization=FINALIZATION_MODEL,
                  source_hashes=dict(primary_aggregate_sha256=sha256(primary).hexdigest(),
                                     primary_aggregate_spare_sha256=sha256(spare).hexdigest(),
                                     pending_extended_write_sha256=EXT_SHA256),
                  cases=cases)
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
    print(f"PASS {len(report['cases'])} BurnNand terminal continuation fixtures")


if __name__ == "__main__":
    main()
