"""Replay Q7's original MD5, hash worker and queue-facing wrappers in synthetic RAM."""
import argparse
from hashlib import md5, sha256
from io import BytesIO
import json
import os
from pathlib import Path
import struct

from check_burn_storage import BOOT_SHA256, HANDLE, RETURN, STACK, base_state, num, read_bytes
from inspect_q7 import parse_elf
from q7_symbols import SHA


INIT, APPEND, FINISH = 0x80043CDC, 0x80043D18, 0x80043E5C
MANAGER, SEND, RECEIVE, LOG = 0x8001B834, 0x80029FDC, 0x80023524, 0x8004717C
WRAPPERS = (0x8001BA40, 0x8001BA74, 0x8001BAAC)
CTX, DATA, OUT = 0x10004000, 0x10005000, 0x10006000
LENGTHS = (0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129)
WORKER_CASES = (
    ("empty", 0, False, None, DATA, False),
    ("abc", 3, False, None, DATA, False),
    ("split", 129, True, None, DATA, False),
    ("mismatch-first", 65, False, 0, DATA, False),
    ("mismatch-last", 65, True, 15, DATA, False),
    ("clear-bit29", 65, False, None, DATA | 0x20000000, False),
    ("set-bit31", 65, True, None, DATA | 0x40000000, False),
    ("unknown-command", 56, True, None, DATA, True),
)
WRAPPER_CASES = (
    ("init", 0, 0, 0, None), ("init-send-status", 0, 7, 0, None),
    ("append", 1, 0, 0, None), ("append-send-status", 1, 7, 0, None),
    ("finish-match", 2, 0, 0, 3), ("finish-mismatch", 2, 0, 0, 4),
    ("finish-stop", 2, 0, 0, 5), ("finish-zero", 2, 0, 0, 0),
    ("finish-statuses-ignored", 2, 7, 9, 3),
)
MODELED = {hex(SEND): "capture three-word queue message and return fixture status",
           hex(RECEIVE): "supply next three-word queue message and return fixture status",
           hex(LOG): "diagnostic log no-op"}


def content(n):
    return b"abc" if n == 3 else bytes((i*17+3) & 255 for i in range(n))


def chunks(n, split):
    return [0, n//3, n-n//3, 0] if split else [n]


def call(project, state, pc, args):
    state.regs.pc, state.regs.ra = pc, RETURN
    for i, value in enumerate(args):
        setattr(state.regs, f"a{i}", value)
    sim = project.factory.simgr(state, save_unconstrained=True)
    sim.explore(find=RETURN, n=10000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, (hex(pc), sim.errored)
    result = sim.found[0]
    assert num(result, result.regs.sp) == STACK
    return result


def primitive_reference():
    return [dict(length=n, chunks=chunks(n, split), digest=md5(content(n)).hexdigest())
            for n in LENGTHS for split in (False, True)]


def primitives(project, angr):
    rows = []
    for expected in primitive_reference():
        data = content(expected["length"])
        st = base_state(project, angr, INIT, ())
        st.memory.store(CTX-8, b"Z"*104)
        st.memory.store(DATA-8, b"Q"*8+data+b"Q"*8)
        st.memory.store(OUT-8, b"R"*32)
        st = call(project, st, INIT, (CTX,))
        pos = 0
        for size in expected["chunks"]:
            st = call(project, st, APPEND, (CTX, DATA+pos, size))
            pos += size
        assert read_bytes(st, CTX, 8) == struct.pack("<Q", len(data)*8)
        st = call(project, st, FINISH, (CTX, OUT))
        row = dict(expected, digest=read_bytes(st, OUT, 16).hex())
        assert row == expected
        assert read_bytes(st, CTX-8, 8) == read_bytes(st, CTX+88, 8) == b"Z"*8
        assert read_bytes(st, OUT-8, 8) == read_bytes(st, OUT+16, 8) == b"R"*8
        assert read_bytes(st, DATA-8, len(data)+16) == b"Q"*8+data+b"Q"*8
        rows.append(row)
    return rows


def worker_reference():
    rows = []
    for name, n, split, mismatch, pointer, unknown in WORKER_CASES:
        digest = md5(content(n)).digest()
        supplied = bytearray(digest)
        if mismatch is not None:
            supplied[mismatch] ^= 0xFF
        requests = [[0, 0, 0]]
        if unknown:
            requests.append([0x99, 0x12345678, 0xABCDEF00])
        pos = 0
        for size in chunks(n, split):
            requests.append([1, pointer+pos, size])
            pos += size
        requests.extend(([2, OUT, 0], [5, 0, 0]))
        normalized = pointer | 0x80000000 if pointer & 0x40000000 else pointer & 0xDFFFFFFF
        rows.append(dict(name=name, length=n, normalized_pointer=hex(normalized),
                         digest=digest.hex(), expected_digest=bytes(supplied).hex(),
                         requests=requests, replies=[[3 if mismatch is None else 4, OUT, 0], [5, 0, 0]]))
    return rows


def workers(project, angr):
    rows = []
    for expected in worker_reference():
        pending, replies = list(expected["requests"]), []

        class Receive(angr.SimProcedure):
            def run(self, queue, target, wait):
                st = self.state
                assert (num(st, queue), num(st, wait)) == (HANDLE+0x127C, 0xFFFFFFFF) and pending
                st.memory.store(num(st, target), struct.pack("<3I", *pending.pop(0)), inspect=False)
                return 0

        class Send(angr.SimProcedure):
            def run(self, queue, source, wait):
                st = self.state
                assert (num(st, queue), num(st, wait)) == (HANDLE+0x12B4, 0)
                replies.append(list(struct.unpack("<3I", read_bytes(st, num(st, source), 12))))
                assert read_bytes(st, STACK-0xB0+0x78, 16).hex() == expected["digest"]
                return 0

        class Log(angr.SimProcedure):
            def run(self):
                return 0

        for address, model in ((RECEIVE, Receive()), (SEND, Send()), (LOG, Log())):
            project.hook(address, model, replace=True)
        st = base_state(project, angr, MANAGER, ())
        address = int(expected["normalized_pointer"], 16)
        data = content(expected["length"])
        guarded = b"Q"*8+data+b"Q"*8
        st.memory.store(address-8, guarded)
        supplied = b"R"*8+bytes.fromhex(expected["expected_digest"])+b"R"*8
        st.memory.store(OUT-8, supplied)
        st = call(project, st, MANAGER, (HANDLE,))
        assert not pending and replies == expected["replies"]
        assert read_bytes(st, address-8, len(guarded)) == guarded
        assert read_bytes(st, OUT-8, len(supplied)) == supplied
        rows.append(dict(expected, replies=replies))
    return rows


def wrapper_reference():
    rows = []
    for name, kind, send_status, receive_status, reply in WRAPPER_CASES:
        request = ([0, 0, 0], [1, DATA, 129], [2, OUT, 0])[kind]
        rows.append(dict(name=name, function=hex(WRAPPERS[kind]), request=request,
                         send_status=send_status, receive_status=receive_status if kind == 2 else None,
                         reply=reply, result=int(reply == 3) if kind == 2 else 1))
    return rows


def wrappers(project, angr):
    rows = []
    for expected in wrapper_reference():
        sends, receives = [], []

        class Send(angr.SimProcedure):
            def run(self, queue, source, wait):
                st = self.state
                assert (num(st, queue), num(st, wait)) == (HANDLE+0x127C, 0)
                sends.append(list(struct.unpack("<3I", read_bytes(st, num(st, source), 12))))
                return expected["send_status"]

        class Receive(angr.SimProcedure):
            def run(self, queue, target, wait):
                st = self.state
                assert (num(st, queue), num(st, wait)) == (HANDLE+0x12B4, 0xFFFFFFFF)
                receives.append(expected["reply"])
                st.memory.store(num(st, target), struct.pack("<3I", expected["reply"], 0, 0), inspect=False)
                return expected["receive_status"]

        project.hook(SEND, Send(), replace=True)
        project.hook(RECEIVE, Receive(), replace=True)
        pc = int(expected["function"], 16)
        st = base_state(project, angr, pc, ())
        args = (HANDLE, DATA, 129) if pc == WRAPPERS[1] else (HANDLE, OUT)
        st = call(project, st, pc, args)
        assert sends == [expected["request"]]
        assert receives == ([] if expected["reply"] is None else [expected["reply"]])
        row = dict(expected, result=num(st, st.regs.v0))
        assert row == expected
        rows.append(row)
    return rows


def validate_report(report):
    if not __debug__:
        raise RuntimeError("Validation requires assertions")
    assert report["input_sha256"] == SHA and report["boot_elf_sha256"] == BOOT_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["primitive_hooks"] == [] and report["modeled_worker_wrappers"] == MODELED
    assert report["primitive_cases"] == primitive_reference()
    assert report["worker_cases"] == worker_reference()
    assert report["wrapper_cases"] == wrapper_reference()


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
    report = dict(input_sha256=SHA, boot_elf_sha256=BOOT_SHA256, engine=f"angr {angr.__version__} / VEX",
                  primitive_hooks=[], primitive_cases=primitives(project, angr),
                  worker_cases=workers(project, angr), wrapper_cases=wrappers(project, angr),
                  modeled_worker_wrappers=MODELED)
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
    print("PASS 26 native MD5, 8 native worker and 9 native wrapper cases; queues/log modeled")


if __name__ == "__main__":
    main()
