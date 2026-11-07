"""Replay five Q7 ISP writers with VEX and synthetic RAM in place of MMIO."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


ELF_SHA256 = "a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796"
SCOPE = "Concrete MIPS replay with synthetic RAM MMIO and a clock stub; no hardware, pixels or camera runtime."
CHECKS = "Trace length, each ordered event, successful return and restored stack; invalid memory accesses trap separately."
SOURCE, STACK_TOP, RETURN_PC, CLOCK = 0x10001000, 0x70001000, 0x0BADF000, 0x8000F6A4


def reference_cases():
    def writes(base, offsets, values):
        return [("write", base + offset, 4, value & 0xFFFFFFFF)
                for offset, value in zip(offsets, values, strict=True)]

    matrix = [-32768, 8192, -17, 32767, -1, 0, 73, -257, 1024]
    mode = 0xFEDC
    extra = [0, 1, 0xDEADBEEF, 0x01234567, 0x80000000, 0xFFFFFFFF]
    for dirty in (0, 1):
        obj = bytearray([0xA5] * 0xC8)
        obj[0x29] = dirty
        struct.pack_into("<9iH", obj, 0x88, *matrix, mode)
        struct.pack_into("<6I", obj, 0xB0, *extra)
        expected = writes(0xB6000000, [*range(0x200, 0x228, 4), *range(0x1A8, 0x1C0, 4)],
                          [*matrix, mode, *extra])
        yield (0x803537A4, f"ccm-dirty-{dirty}", dict(dirty=dirty, signed_i32=matrix, mode_u16=mode,
               extra_u32=extra), obj, (SOURCE,), 0x10, expected if dirty else [])

    tail = [-129, -32767]
    flags = 0xF12E34A5
    fc1_offsets = [*range(0xC0, 0xEC, 4), 0xFC]
    fc2_offsets = [0x840, 0x84C, 0x858, 0x844, 0x850, 0x85C, 0x848, 0x854, 0x860, 0x864, 0x868, 0x870]
    for address, name, offsets in ((0x8031F750, "fc1", fc1_offsets), (0x80354970, "fc2", fc2_offsets)):
        expected = writes(0xB6000000, offsets, [*matrix, *tail, flags])
        for dirty in (0, 1):
            obj = bytearray([0xA5] * 0x4C)
            obj[0x29] = dirty
            struct.pack_into("<11h", obj, 0x30, *matrix, *tail)
            struct.pack_into("<I", obj, 0x48, flags)
            yield (address, f"{name}-dirty-{dirty}", dict(dirty=dirty, matrix_i16=matrix, tail_i16=tail,
                   flags_u32=flags), obj, (SOURCE,), 0x20, expected if dirty else [])

    first, step = 0x10203040, 0x07132531
    clock_on, clock_off = ("clock", 14, 1), ("clock", 14, 0)
    for name, count in (("gamma", 77), ("dci", 0), ("dci", 1), ("dci", 3)):
        words = [(first + step * i) & 0xFFFFFFFF for i in range(count)]
        if name == "gamma":
            addr, args, frame = 0x801D585C, (SOURCE,), 0x18
            expected = [("write", 0xB500206C, 4, 0), *writes(0xB5000000, [0x2070] * count, words),
                        ("write", 0xB500204C, 4, 0)]
        else:
            addr, args, frame = 0x801D58C4, (SOURCE, count), 0x20
            expected = [("write", 0xB5002430, 4, 0), *writes(0xB5000000, [0x2434] * count, words)]
        yield (addr, f"{name}-{count}", dict(words=count, first_u32=first, step_u32=step),
               struct.pack(f"<{count}I", *words), args, frame, [clock_on, *expected, clock_off])


def case_result(case, events):
    address, name, setup, payload, _, _, _ = case
    return dict(address=address, case=name, input=setup, input_sha256=hashlib.sha256(payload).hexdigest(),
                mmio_writes=sum(event[0] == "write" for event in events),
                clock_stub_calls=sum(event[0] == "clock" for event in events), assertions=len(events) + 3,
                trace_sha256=hashlib.sha256(json.dumps(events, separators=(",", ":")).encode("ascii")).hexdigest(),
                passed=True)


def validate_report(report):
    """Check the public report against the reference fixtures without angr or firmware."""
    engine = report.get("engine", "")
    if not (isinstance(engine, str) and engine.startswith("angr ") and engine.endswith(" / VEX")):
        raise ValueError("invalid ISP replay engine")
    expected = [case_result(case, case[-1]) for case in reference_cases()]
    if report != dict(analysis_elf_sha256=ELF_SHA256, engine=engine, scope=SCOPE, checks=CHECKS, cases=expected):
        raise ValueError("ISP replay report does not match the reference fixtures")


def replay(project, angr, case):
    address, name, _, payload, args, frame, expected = case
    events = []
    state = project.factory.call_state(address, *args, ret_addr=RETURN_PC,
                                      prototype="void f(void *, unsigned int)" if len(args) == 2 else "void f(void *)",
                                      add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp = STACK_TOP
    state.globals["isp_events"] = events
    if payload:
        state.memory.store(SOURCE, bytes(payload))

    def concrete(s, *expressions):
        if any(s.solver.symbolic(expr) for expr in expressions):
            raise RuntimeError(f"{name}: symbolic memory operation")
        return tuple(s.solver.eval(expr) for expr in expressions)

    def on_read(s):
        access = s.inspect.attrs
        addr, width = concrete(s, access.mem_read_address, access.mem_read_length)
        if not (STACK_TOP - frame <= addr < addr + width <= STACK_TOP or
                SOURCE <= addr < addr + width <= SOURCE + len(payload)):
            raise RuntimeError(f"{name}: out-of-range read at {addr:#010x} ({width} bytes)")

    def on_write(s):
        access = s.inspect.attrs
        addr, width, value = concrete(s, access.mem_write_address, access.mem_write_length, access.mem_write_expr)
        if STACK_TOP - frame <= addr < addr + width <= STACK_TOP:
            return
        if addr >> 24 not in (0xB5, 0xB6):
            raise RuntimeError(f"{name}: out-of-range write at {addr:#010x} ({width} bytes)")
        events.append(("write", addr, width, value))

    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=on_read)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, action=on_write)
    simulation = project.factory.simgr(state, save_unconstrained=True)
    simulation.explore(find=RETURN_PC, n=128)
    if (len(simulation.found) != 1 or simulation.active or simulation.unconstrained
            or simulation.errored or simulation.deadended):
        raise RuntimeError(f"{name}: incomplete replay: {simulation}; {simulation.errored}")
    if concrete(simulation.found[0], simulation.found[0].regs.sp) != (STACK_TOP,):
        raise RuntimeError(f"{name}: stack pointer was not restored")
    if len(events) != len(expected):
        raise RuntimeError(f"{name}: got {len(events)} trace events; expected {len(expected)}")
    for i, (actual, want) in enumerate(zip(events, expected, strict=True)):
        if actual != want:
            raise RuntimeError(f"{name}: event {i}: got {actual!r}; expected {want!r}")
    return case_result(case, events)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    if hashlib.sha256(args.elf.read_bytes()).hexdigest() != ELF_SHA256:
        parser.error("input ELF does not match the analyzed firmware SHA-256")

    import angr

    class ClockStub(angr.SimProcedure):
        def run(self, unit, enabled):
            self.state.globals["isp_events"].append(("clock", self.state.solver.eval_one(unit),
                                                    self.state.solver.eval_one(enabled)))

    project = angr.Project(str(args.elf), auto_load_libs=False)
    if project.arch.name != "MIPS32" or project.arch.memory_endness != "Iend_LE":
        raise RuntimeError("expected a little-endian MIPS32 ELF")
    project.hook(CLOCK, ClockStub())
    cases = [replay(project, angr, case) for case in reference_cases()]
    result = dict(analysis_elf_sha256=ELF_SHA256, engine=f"angr {angr.__version__} / VEX",
                  scope=SCOPE, checks=CHECKS, cases=cases)
    validate_report(result)
    with args.output.open("x", encoding="utf-8", newline="\n") as out:
        out.write(json.dumps(result, indent=2) + "\n")
    print(f"{len(cases)} ISP register replay cases passed ({sum(case['assertions'] for case in cases)} checks)")


if __name__ == "__main__":
    main()
