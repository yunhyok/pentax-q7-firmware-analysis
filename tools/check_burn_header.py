"""Attribute the first Q7 program-buffer changes and replay its MBR field writer."""
import argparse
from collections import defaultdict
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import struct

import check_burn_storage as storage
from inspect_q7 import parse_elf
from q7_symbols import SHA


MBR_WRITER = 0x8001A3A8
COPY_PCS = tuple(range(0x80013E88, 0x80013EA8, 4))
EVENT_COUNTS = {
    0x80012FCC: 1, 0x80012FD0: 1, 0x8001AF50: 1, 0x8001AF54: 1, 0x8001AF58: 1,
    0x8001AF78: 8, 0x8001AF7C: 8, 0x8001AF80: 8, 0x8001AF84: 8, 0x8001A95C: 1,
    0x8001A410: 16, 0x8001A414: 16, 0x8001A420: 16, 0x8001A424: 16,
    0x8001A428: 4, 0x8001A3EC: 1, 0x8001AC48: 2, 0x8001AC4C: 2,
    0x8001AC50: 2, 0x8001AC54: 2, 0x8001AC68: 1, 0x8001AC8C: 13,
    0x8001AC90: 13, 0x8001AC94: 13, 0x8001AC98: 13, 0x8001ACB0: 1, 0x8001ACB4: 1,
    **{pc: 384 for pc in COPY_PCS},
}
CHANGED_RANGES = [[0x214, 0x215], [0x238, 0x318], [0x3A8, 0x3D4], [0x5BE, 0x5BF],
                  [0x5C2, 0x5C3], [0x5C7, 0x5C9], [0x5CB, 0x5CC], [0x5D2, 0x5D3],
                  [0x5D6, 0x5D7], [0x5DA, 0x5DB], [0x5E2, 0x5E3], [0x5E7, 0x5E8],
                  [0x5F2, 0x5F3], [0x5F7, 0x5F8]]
PARTITIONS = [dict(id=i, raw_byte0=0x80, raw_byte4=1, raw_u32_at8=start, raw_u32_at12=count)
              for i, (start, count) in enumerate(((81920, 24576), (13280, 68640), (106496, 4096), (110592, 53248)))]
MBR_CASES = ((999, 1), (999, 0), (0, 1), (1, 1), (2, 1), (3, 1), (2, 0))
MBR, SECTION = 0x10004000, 0x10005000
EVENT_ENCODING = "VEX memory-write events, not logical store-instruction executions; SWL/SWR may expand into byte events"


def ranges(offsets):
    result = []
    for offset in offsets:
        if result and result[-1][1] == offset:
            result[-1][1] += 1
        else:
            result.append([offset, offset+1])
    return result


def trace(project, angr, firmware):
    events = []

    def observe(state):
        def write(st):
            if st.scratch.ins_addr is None or project.is_hooked(st.addr):
                return
            address = storage.num(st, st.inspect.attrs.mem_write_address)
            length = st.inspect.attrs.mem_write_length
            size = st.inspect.attrs.mem_write_expr.size()//8 if length is None else storage.num(st, length)
            if address < storage.PRIMARY+storage.CHUNK and address+size > storage.PRIMARY:
                assert storage.PRIMARY <= address and address+size <= storage.PRIMARY+storage.CHUNK
                events.append((st.scratch.ins_addr, address-storage.PRIMARY, storage.read_bytes(st, address, size)))
        state.inspect.b("mem_write", when=angr.BP_AFTER, action=write)

    prefix = storage.replay_prefix(project, angr, firmware, observe=observe)
    assert prefix["pending_data"] == storage.PENDING_DATA
    original = firmware[storage.CARD_OFFSET:storage.CARD_OFFSET+storage.CHUNK]
    reconstructed, before_copy = bytearray(original), bytearray(original)
    groups = defaultdict(list)
    for pc, offset, data in events:
        if pc in COPY_PCS:
            assert reconstructed[offset:offset+len(data)] == data
        reconstructed[offset:offset+len(data)] = data
        if pc not in COPY_PCS:
            before_copy[offset:offset+len(data)] = data
        groups[pc].append((offset, data))
    assert sha256(reconstructed).hexdigest() == prefix["pending_data"]["program_source_sha256"]
    assert before_copy == reconstructed
    assert {pc: len(rows) for pc, rows in groups.items()} == EVENT_COUNTS
    changed = ranges(i for i, (a, b) in enumerate(zip(original, reconstructed, strict=True)) if a != b)
    assert changed == CHANGED_RANGES
    partitions = []
    mbr_offset = struct.unpack_from("<I", reconstructed, 0x200)[0]*512
    assert mbr_offset == 0x400
    for i in range(4):
        start = mbr_offset+0x1BE+i*16
        partitions.append(dict(id=i, raw_byte0=reconstructed[start], raw_byte4=reconstructed[start+4],
                               raw_u32_at8=struct.unpack_from("<I", reconstructed, start+8)[0],
                               raw_u32_at12=struct.unpack_from("<I", reconstructed, start+12)[0]))
    assert partitions == PARTITIONS
    assert struct.unpack_from("<I", reconstructed, 0x214)[0] == 0x13600
    assert struct.unpack_from("<2I", reconstructed, 0x310) == (640, 384)
    assert struct.unpack_from("<2I", reconstructed, 0x3A8) == (1, 0)
    return dict(source=prefix["pending_data"], first_program_request=prefix["first_operation_5"],
                event_encoding=EVENT_ENCODING,
                event_count=len(events), before_copy_events=sum(len(v) for k, v in groups.items() if k not in COPY_PCS),
                final_copy_events=sum(len(groups[pc]) for pc in COPY_PCS),
                final_copy_byte_preserving=True, changed_ranges_end_exclusive=changed,
                mbr_offset=mbr_offset, partition_fields=partitions,
                fields={"0x214": 0x13600, "0x310": 640, "0x314": 384, "0x3a8": 1, "0x3ac": 0},
                groups=[dict(pc=hex(pc), events=len(rows), min_offset=min(off for off, _ in rows),
                             end_exclusive=max(off+len(data) for off, data in rows),
                             offset_size_data_sha256=sha256(b"".join(struct.pack("<2I", off, len(data))+data for off, data in rows)).hexdigest())
                        for pc, rows in sorted(groups.items())])


def mbr_reference():
    return [dict(partition_id=pid, span=span, writes=bool(pid != 999 and span),
                 boot_byte=0x80 if pid == 0 and span else 0xA5,
                 length=0x9ABCDEF0 if pid != 999 and span else None,
                 start=0x12345678 if pid != 999 and span else None)
            for pid, span in MBR_CASES]


def replay_mbr(project, angr):
    class Log(angr.SimProcedure):
        def run(self):
            return 0
    project.hook(0x8004717C, Log(), replace=True)
    rows = []
    for expected in mbr_reference():
        pid, span = expected["partition_id"], expected["span"]
        st = storage.base_state(project, angr, MBR_WRITER, (MBR, 0, SECTION))
        initial = b"G"*8+b"\xa5"*512+b"G"*8
        section = struct.pack("<9I", 123, span, 234, pid, 0x9ABCDEF0, 0x12345678, 345, 456, 567)
        st.memory.store(MBR-8, initial)
        st.memory.store(SECTION-8, b"S"*8+section+b"S"*8)
        sim = project.factory.simgr(st, save_unconstrained=True)
        sim.explore(find=storage.RETURN, n=100)
        assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, sim
        final = sim.found[0]
        want = bytearray(initial)
        if expected["writes"]:
            offset = 8+0x1BE+16*pid
            if pid == 0:
                want[offset] = 0x80
            want[offset+4] = 1
            struct.pack_into("<2I", want, offset+8, expected["start"], expected["length"])
        assert storage.read_bytes(final, MBR-8, len(initial)) == want
        assert storage.read_bytes(final, SECTION-8, len(section)+16) == b"S"*8+section+b"S"*8
        assert storage.num(final, final.regs.sp) == storage.STACK
        rows.append(expected)
    return rows


def validate_report(report):
    if not __debug__:
        raise RuntimeError("Validation requires assertions")
    assert report["input_sha256"] == SHA and report["boot_elf_sha256"] == storage.BOOT_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["modeled_prefix"] == storage.modeled(storage.PREFIX_HOOKS)
    assert report["modeled_mbr"] == {"0x8004717c": "diagnostic log no-op"}
    t = report["trace"]
    assert t["event_encoding"] == EVENT_ENCODING
    assert t["source"] == storage.PENDING_DATA and t["first_program_request"] == storage.reference_prefix()["first_operation_5"]
    assert (t["event_count"], t["before_copy_events"], t["final_copy_events"], t["final_copy_byte_preserving"]) == (3242, 170, 3072, True)
    assert t["changed_ranges_end_exclusive"] == CHANGED_RANGES
    assert sum(hi-lo for lo, hi in CHANGED_RANGES) == 281
    assert t["mbr_offset"] == 0x400 and t["partition_fields"] == PARTITIONS
    assert {int(g["pc"], 16): g["events"] for g in t["groups"]} == EVENT_COUNTS
    # Pin complete ordered groups, including ranges, event digests and duplicate PCs.
    assert sha256(json.dumps(t["groups"], sort_keys=True, separators=(",", ":")).encode()).hexdigest() == "591c7ef56c0127b96c01b56671af4b735c6ba9aee3b57f91ef940d47cec98250"
    assert t["fields"] == {"0x214": 0x13600, "0x310": 640, "0x314": 384, "0x3a8": 1, "0x3ac": 0}
    assert report["mbr_cases"] == mbr_reference()


def replay(firmware):
    if not __debug__:
        raise RuntimeError("Replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    boot, _ = parse_elf(firmware, 0x200)
    if boot["sha256_referenced_bytes"] != storage.BOOT_SHA256:
        raise ValueError("unexpected E01 boot ELF extent")
    import angr
    project = angr.Project(BytesIO(firmware[0x200:boot["referenced_end"]]), auto_load_libs=False)
    report = dict(input_sha256=SHA, boot_elf_sha256=storage.BOOT_SHA256, engine=f"angr {angr.__version__} / VEX",
                  trace=trace(project, angr, firmware), mbr_cases=replay_mbr(project, angr),
                  modeled_prefix=storage.modeled(storage.PREFIX_HOOKS),
                  modeled_mbr={"0x8004717c": "diagnostic log no-op"})
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error("replay requires assertions")
    if os.path.lexists(args.output):
        parser.error("output must not exist")
    report = replay(args.firmware.read_bytes())
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("PASS 3242 VEX writes reconstruct 281 changed bytes; 7 native MBR field-writer cases")


if __name__ == "__main__":
    main()
