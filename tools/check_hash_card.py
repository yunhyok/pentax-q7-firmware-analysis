"""Replay Q7 card hash verification through the original wrappers and MD5 worker."""
import argparse
from hashlib import md5, sha256
from io import BytesIO
import json
from os.path import lexists
from pathlib import Path
import struct

from check_burn_hash import LOG, MANAGER, RECEIVE, SEND, call
from check_burn_storage import BOOT_SHA256, HANDLE, STACK, base_state, num, put_u32, read_bytes, u32
from inspect_q7 import parse_elf
from q7_symbols import SHA


CARD = 0x80019014
READ, SEEK = 0x800632F4, 0x800622E0
ALLOC, FREE, CACHE = 0x80034720, 0x80034D98, 0x80048CF8
DEST, TEMP, FILE = 0x10002000, 0x10003000, 0x10006000
LENGTH, DIGEST_BYTES, GUARD = 64, 16, 8
REQUESTS = ((0,0,0), (1,DEST,LENGTH), (2,DEST+LENGTH,0))
STOP = (5,0,0)
CANARY = b"\xA5"*GUARD
INITIAL = b"\xEE"*(LENGTH+DIGEST_BYTES)
SPECS = (
    ("match", ((0, None),), (), 1),
    ("first-digest-byte-retry-match", ((0, 0), (0, None)), (0,), 1),
    ("last-digest-byte-retry-new-payload", ((0, 15), (1, None)), (0,), 1),
    ("first-and-last-digest-byte-fail", ((0, 0), (0, 15)), (0, 0), 0),
    ("digest-mismatch-seek-error", ((0, 15),), (1,), 0),
    ("file-read-error", ((None, None),), (), 0),
    ("digest-mismatch-retry-read-error", ((0, 0), (None, None)), (0,), 0),
)
SCOPE = (
    "Original E01 card callback, hash wrappers, hash manager, MD5 and digest comparison. "
    "Each blocking result receive serially runs the worker on a separate project/state loaded "
    "from the same pinned E01 bytes. The exact callback destination/handle RAM is copied; "
    "worker stack and register writes are discarded. Only a native reply 3 or 4 is delivered "
    "to the original callback wrapper. Stop 5 is a fixture message for ending the worker."
)
MODELED = {
    hex(READ): "Deliver the fixture's full 80-byte data/digest record or read status 1 with actual count zero.",
    hex(SEEK): "Record original file, distance, high word and mode and return fixture status. No FileX media I/O.",
    hex(ALLOC): "Supply synthetic comparison RAM for the callback's allocation, including in flag-1 mode.",
    hex(CACHE): "Observe comparison RAM invalidation request without modifying cache.",
    hex(FREE): "Record the release of the synthetic comparison RAM.",
    hex(SEND): "Capture original three-word records; do not run RTOS queue send.",
    hex(RECEIVE): "Deliver captured records, controlled worker stop, or the worker's native reply. No RTOS scheduling.",
    hex(LOG): "Accept diagnostic output without I/O.",
}


def payload(variant):
    return bytes(range(LENGTH)) if variant == 0 else bytes(255-i for i in range(LENGTH))


def digest(data):
    return md5(data, usedforsecurity=False).digest()


def record_bytes(variant, mismatch):
    data = payload(variant)
    supplied = bytearray(digest(data))
    if mismatch is not None:
        supplied[mismatch] ^= 0xFF
    return data + supplied


def reference():
    rows = []
    for name, reads, seeks, result in SPECS:
        events, workers = [], []
        seek_index = 0
        for variant, mismatch in reads:
            events.append(["read", FILE, DEST, LENGTH+DIGEST_BYTES,
                           0 if variant is None else LENGTH+DIGEST_BYTES, int(variant is None)])
            if variant is None:
                free_line = 0x1B3
                break
            block = record_bytes(variant, mismatch)
            response = [3 if mismatch is None else 4, DEST+LENGTH, 0]
            workers.append(dict(payload_variant=variant, mismatch_index=mismatch,
                                calculated_md5=digest(block[:LENGTH]).hex(),
                                supplied_md5=block[LENGTH:].hex(), worker_requests=[list(m) for m in (*REQUESTS,STOP)],
                                worker_replies=[response,list(STOP)], delivered_reply=response))
            if mismatch is None:
                free_line = 0x1CF
                break
            status = seeks[seek_index]
            seek_index += 1
            events.append(["seek",FILE,LENGTH+DIGEST_BYTES,0,3,status])
            free_line = 0x1C6 if status else 0x207
            if status:
                break
        events.append(["free", TEMP, free_line])
        rows.append(dict(name=name, hash_flag=1, result=result, callback_events=events, workers=workers))
    return dict(input_sha256=SHA, boot_elf_sha256=BOOT_SHA256, scope=SCOPE,
                modeled_boundaries=MODELED, synthetic_payload_bytes=LENGTH,
                trailing_digest_bytes=DIGEST_BYTES, cases=rows)


def validate_report(report):
    """Validate public fixture metadata with the standard library."""
    engine = report.get("engine")
    if (not isinstance(engine, str) or not engine.startswith("angr ") or not engine.endswith(" / VEX")
            or report != dict(reference(), engine=engine)):
        raise ValueError("Card hash replay report differs from the reference")


def record(state, key, row):
    state.globals[key] = (*state.globals.get(key, ()), row)


def queue_words(state, pointer):
    return list(struct.unpack("<3I", read_bytes(state, num(state, pointer), 12)))


def store_words(state, pointer, words):
    state.memory.store(num(state,pointer), struct.pack("<3I",*words), inspect=False)


def guard_native_writes(state, angr):
    def on_write(st):
        address = num(st, st.inspect.attrs.mem_write_address)
        length = num(st, st.inspect.attrs.mem_write_length)
        assert STACK-0x1000 <= address < address+length <= STACK+0x1000, (hex(st.addr),hex(address),length)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_write)


def install_worker(project, angr):
    class WorkerReceive(angr.SimProcedure):
        def run(self, queue, target, wait):
            st = self.state
            assert (num(st,queue),num(st,wait)) == (HANDLE+0x127C,0xFFFFFFFF)
            head, *tail = st.globals["pending"]
            st.globals["pending"] = tuple(tail)
            record(st,"received",list(head))
            store_words(st,target,head)
            return 0

    class WorkerSend(angr.SimProcedure):
        def run(self, queue, source, wait):
            st = self.state
            assert (num(st,queue),num(st,wait)) == (HANDLE+0x12B4,0)
            record(st,"replies",queue_words(st,source))
            return 0

    project.hook(RECEIVE, WorkerReceive())
    project.hook(SEND, WorkerSend())


def run_worker(parent, project, angr, pending):
    assert len(pending) == 3 and tuple(tuple(row) for row in pending) == REQUESTS
    st = base_state(project, angr, MANAGER, ())
    guarded = read_bytes(parent, DEST-GUARD, 2*GUARD+LENGTH+DIGEST_BYTES)
    handle = read_bytes(parent,HANDLE,0x2000)
    st.memory.store(DEST-GUARD, guarded)
    st.memory.store(HANDLE,handle)
    st.globals["pending"] = (*pending,STOP)
    guard_native_writes(st,angr)
    st = call(project,st,MANAGER,(HANDLE,))
    assert not st.globals["pending"] and st.globals["received"] == (*pending,list(STOP))
    first, stop = st.globals["replies"]
    assert first[0] in (3,4) and first[1:] == [DEST+LENGTH,0] and stop == list(STOP)
    assert read_bytes(st,DEST-GUARD,len(guarded)) == guarded and read_bytes(st,HANDLE,0x2000) == handle
    return (list(st.globals["received"]),list(st.globals["replies"]),
            read_bytes(st,STACK-0xB0+0x78,DIGEST_BYTES))


def install_card(project, worker_project, angr):
    class Allocate(angr.SimProcedure):
        def run(self, pool, size, align, caller):
            st = self.state
            assert (num(st,pool),num(st,size),num(st,align)) == (0,LENGTH,1)
            record(st,"allocations",TEMP)
            return TEMP

    class Invalidate(angr.SimProcedure):
        def run(self, pointer, size):
            st = self.state
            assert (num(st,pointer),num(st,size)) == (TEMP,LENGTH)
            record(st,"invalidations",TEMP)
            return 0

    class Free(angr.SimProcedure):
        def run(self, pool, pointer, caller, line):
            st = self.state
            assert (num(st,pool),num(st,pointer)) == (0,TEMP)
            record(st,"events",["free",TEMP,num(st,line)])
            return 0

    class Read(angr.SimProcedure):
        def run(self, handle, dest, size, actual):
            st = self.state
            assert (num(st,handle),num(st,dest),num(st,size)) == (FILE,DEST,LENGTH+DIGEST_BYTES)
            current, *tail = st.globals["reads"]
            st.globals["reads"] = tuple(tail)
            st.globals["current"] = current
            variant, mismatch = current
            block = b"" if variant is None else record_bytes(variant,mismatch)
            if block:
                st.memory.store(DEST,block,inspect=False)
                st.globals["last_block"] = block
            put_u32(st,num(st,actual),len(block))
            status = int(variant is None)
            record(st,"events",["read",FILE,DEST,LENGTH+DIGEST_BYTES,len(block),status])
            return status

    class Seek(angr.SimProcedure):
        def run(self, handle, padding, low, high):
            st = self.state
            option = u32(st,num(st,st.regs.sp)+16)
            args = [num(st,a) for a in (handle,low,high)] + [option]
            assert args == [FILE,LENGTH+DIGEST_BYTES,0,3]
            status, *tail = st.globals["seeks"]
            st.globals["seeks"] = tuple(tail)
            record(st,"events",["seek",*args,status])
            return status

    class CallbackSend(angr.SimProcedure):
        def run(self, queue, source, wait):
            st = self.state
            assert (num(st,queue),num(st,wait)) == (HANDLE+0x127C,0)
            record(st,"requests",queue_words(st,source))
            return 0

    class CallbackReceive(angr.SimProcedure):
        def run(self, queue, target, wait):
            st = self.state
            assert (num(st,queue),num(st,wait)) == (HANDLE+0x12B4,0xFFFFFFFF)
            commands, replies, calculated = run_worker(st,worker_project,angr,st.globals.pop("requests"))
            variant, mismatch = st.globals.pop("current")
            supplied = read_bytes(st,DEST+LENGTH,DIGEST_BYTES)
            assert calculated == digest(read_bytes(st,DEST,LENGTH))
            record(st,"workers",dict(payload_variant=variant,mismatch_index=mismatch,
                                     calculated_md5=calculated.hex(),supplied_md5=supplied.hex(),
                                     worker_requests=commands,worker_replies=replies,delivered_reply=replies[0]))
            store_words(st,target,replies[0])
            return 0

    class Log(angr.SimProcedure):
        def run(self):
            return 0

    for address, model in ((ALLOC,Allocate()), (CACHE,Invalidate()), (FREE,Free()), (READ,Read()), (SEEK,Seek()),
                           (SEND,CallbackSend()), (RECEIVE,CallbackReceive()), (LOG,Log())):
        project.hook(address,model)
    worker_project.hook(LOG,Log())


def replay(firmware):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    boot, _ = parse_elf(firmware,0x200)
    if boot["sha256_referenced_bytes"] != BOOT_SHA256:
        raise ValueError("unexpected E01 boot ELF extent")
    import angr
    boot_bytes = firmware[0x200:boot["referenced_end"]]
    project = angr.Project(BytesIO(boot_bytes),auto_load_libs=False)
    worker_project = angr.Project(BytesIO(boot_bytes),auto_load_libs=False)
    install_worker(worker_project,angr)
    install_card(project,worker_project,angr)
    rows = []
    for name, reads, seeks, _ in SPECS:
        st = base_state(project,angr,CARD,())
        put_u32(st,0x800A7770,HANDLE)
        put_u32(st,0x800C7438,FILE)
        st.memory.store(HANDLE+0x1278,b"\x01",inspect=False)
        st.memory.store(DEST-GUARD,CANARY+INITIAL+CANARY,inspect=False)
        st.memory.store(TEMP-GUARD,b"T"*(LENGTH+2*GUARD),inspect=False)
        st.globals["reads"], st.globals["seeks"] = reads, seeks
        guard_native_writes(st,angr)
        st = call(project,st,CARD,(LENGTH,DEST))
        assert not st.globals["reads"] and not st.globals["seeks"] and not st.globals.get("requests")
        assert st.globals["allocations"] == st.globals["invalidations"] == (TEMP,)
        expect = st.globals.get("last_block",INITIAL)
        assert read_bytes(st,DEST-GUARD,len(expect)+2*GUARD) == CANARY+expect+CANARY
        assert read_bytes(st,TEMP-GUARD,LENGTH+2*GUARD) == b"T"*(LENGTH+2*GUARD)
        rows.append(dict(name=name,hash_flag=u32(st,HANDLE+0x1278)&0xFF,result=num(st,st.regs.v0),
                         callback_events=list(st.globals["events"]),workers=list(st.globals.get("workers",()))))
    report = dict(reference(),engine=f"angr {angr.__version__} / VEX",cases=rows)
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
    with args.output.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(report,stream,indent=2)
        stream.write("\n")
    workers = sum(len(row["workers"]) for row in report["cases"])
    print(f"PASS {len(report['cases'])} native card callbacks and {workers} native hash worker transactions")


if __name__ == "__main__":
    main()

