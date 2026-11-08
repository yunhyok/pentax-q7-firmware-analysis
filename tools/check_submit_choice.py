"""Replay Q7 HDR output descriptor selection on the pinned analysis ELF."""
import argparse
import json
import struct
from pathlib import Path
from check_isp_registers import ELF_SHA256, load_project

ELF_SHA256 = "a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796"
RETURN, STACK = 0x0BADF000, 0x70002000
PATH, POOL, INPUT, OUTPUT = 0x10001000, 0x10002000, 0x10003000, 0x10004000
CONTROL, FILTER, LUT = 0x10005000, 0x10006000, 0x10007000
ALT_BLOCK, ALT_DESCRIPTOR, ALT_BUFFER = 0x10008000, 0x10009000, 0x20009000
INPUT_BUFFER, OUTPUT_BUFFER = 0x20003000, 0x20004000
SET_IMAGE, BEFORE_SUBMIT = 0x80337D14, 0x80B1C330
SCOPE = "Original ConvertPathInit, HDR caller, type-0 creation and descriptor setters/selector. Stops at SetImage(kind=2); allocation, RTOS calls and hardware setup are modeled."
ZERO_STUBS = {
    0x801D12F4: "IpuInit",
    0x800D9AC8: "_tx_counter_get",
    0x800D9DF0: "_tx_thread_interrupt_control",
    0x800CDB00: "_tx_mutex_create",
    0x800CBEE4: "_tx_mutex_get",
    0x800D193C: "_tx_mutex_put",
    0x803383F8: "CImageProcessor constructor",
    0x800B6A40: "CObserver constructor",
    0x800AD164: "CObservable::Register",
}


def replay(elf):
    if not __debug__:
        raise RuntimeError("Replay requires assertions")
    import angr
    project = load_project(elf)

    def concrete(state, expression):
        assert not expression.symbolic
        return state.solver.eval(expression)

    def read(state, address, size=4):
        return concrete(state, state.memory.load(address, size, endness="Iend_LE"))

    class NoOp(angr.SimProcedure):
        def run(self):
            return 0

    class EarlierSetImage(angr.SimProcedure):
        def run(self, processor, descriptor, kind):
            assert concrete(self.state, kind) in (0, 1, 5)
            return 0

    class Allocate(angr.SimProcedure):
        def run(self, a0, a1, a2, *, size_arg):
            size = concrete(self.state, (a0, a1, a2)[size_arg])
            assert 0 < size <= 0x2000
            if size == 0xB40 and size_arg == 1:
                address, fill = PATH, 0xA5
            else:
                index = self.state.globals.get("allocation_count", 0)
                self.state.globals["allocation_count"] = index + 1
                address, fill = 0x12000000 + index * 0x2000, 0
            self.state.memory.store(address, bytes([fill]) * size)
            return address

    for address in ZERO_STUBS:
        project.hook(address, NoOp())
    allocation_stubs = {
        0x8000BF28: ("PoolAllocEx", 1),
        0x8000D8BC: ("operator new", 0),
        0x80B1F120: ("MemAlloc", 0),

    }
    for address, (_, size_arg) in allocation_stubs.items():
        project.hook(address, Allocate(size_arg=size_arg))
    project.hook(SET_IMAGE, EarlierSetImage())

    def advance(state, find):
        sim = project.factory.simgr(state)
        sim.explore(find=find, n=1024)
        if len(sim.found) != 1 or sim.active or sim.errored:
            raise RuntimeError(f"Replay failed at {state.addr:#x}: {sim}. {sim.errored}")
        return sim.found[0]

    def call(state, pc, args, stop=RETURN):
        state.regs.pc, state.regs.ra = pc, RETURN
        for i, value in enumerate(args):
            setattr(state.regs, f"a{i}", value)
        return advance(state, stop)

    def put_block(state, address, buffer):
        state.memory.store(address, struct.pack("<7I", buffer, 64, 16, 0, 0, 64, 16))

    def result(state, name, expected_buffer, expected_selector):
        assert read(state, PATH + 0x964) == expected_selector
        assert read(state, PATH + 0x28) == OUTPUT_BUFFER
        state = advance(state, lambda s: s.addr == SET_IMAGE and concrete(s, s.regs.a2) == 2)
        branch = 0x801D0BA0 if expected_selector else 0x801D0CC4
        assert branch in state.history.bbl_addrs
        descriptor = concrete(state, state.regs.a1)
        assert concrete(state, state.regs.a0) == read(state, PATH + 0x880)
        assert read(state, descriptor) == expected_buffer
        assert read(state, descriptor + 0x68) == 8
        assert read(state, descriptor + 0x6C, 1) == 1
        return dict(name=name, path_output=hex(OUTPUT_BUFFER), selector=expected_selector, selector_destination=hex(branch),
                    submitted_surface=hex(expected_buffer), image_type=8, image_kind=2)

    state = project.factory.blank_state(addr=0x801BCEFC, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,

    })
    state.regs.sp = STACK
    state.memory.store(POOL, bytes(0x40))
    state.memory.store(0x801E3824, bytes(0x68))
    state = call(state, 0x801BCEFC, [POOL])
    assert read(state, 0x801E3824) == 0xB40
    assert read(state, 0x801E3870) == 0x801BCC48
    put_block(state, INPUT, INPUT_BUFFER)
    put_block(state, OUTPUT, OUTPUT_BUFFER)
    put_block(state, ALT_BLOCK, ALT_BUFFER)
    state.memory.store(FILTER, struct.pack("<5I", 0x14, 0xCB, 0, 0, 0))
    state.memory.store(CONTROL, struct.pack("<4I", 0, 0, LUT, FILTER))
    state.memory.store(LUT, bytes(0x400))
    state = call(state, 0x80B1C104, [INPUT, OUTPUT, 0x0F01, CONTROL], BEFORE_SUBMIT)
    assert read(state, PATH + 4) == 0
    assert read(state, PATH + 0xB8, 2) == 0x0F01
    assert read(state, PATH + 0xBA, 2) == 0
    assert read(state, PATH + 0x8F0) == 0
    assert state.solver.eval(state.memory.load(PATH + 0x8FC, 0x74), cast_to=bytes) == bytes(0x74)

    normal = result(state.copy(), "fresh_hdr_type0", OUTPUT_BUFFER, 0)
    alternate = call(state.copy(), 0x8009FB70, [ALT_DESCRIPTOR, ALT_BLOCK, 8])
    alternate = call(alternate, 0x801BB4C4, [PATH, 9, ALT_DESCRIPTOR])
    alternate.regs.pc = BEFORE_SUBMIT
    alternate.regs.ra = state.regs.ra
    counterfactual = result(alternate, "explicit_descriptor_id9_counterfactual", ALT_BUFFER, 8)
    return dict(
        analysis_elf_sha256=ELF_SHA256,
        scope=SCOPE,
        stubs={f"0x{a:08x}": name for a, name in {
            **ZERO_STUBS,
            **{a: name for a, (name, _) in allocation_stubs.items()},
            SET_IMAGE: "SetImage kinds 0, 1 and 5 only",
        }.items()},
        cases=[normal, counterfactual],
        limitations=[
            "Synthetic descriptors and successful software calls, with firmware memory initialized where needed.",
            "No physical memory accesses, image writes, camera pixels or hardware execution.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    result = replay(args.elf)
    with args.output.open("x", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=2) + "\n")
    print("2 output descriptor cases PASS")


if __name__ == "__main__":
    main()
