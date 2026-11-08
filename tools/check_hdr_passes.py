"""Replay fresh Q7 HDR pass selection through a bounded software path."""
import argparse
import json
import struct
from pathlib import Path
from check_isp_registers import ELF_SHA256, load_project

from check_submit_choice import ELF_SHA256

RETURN, STACK = 0x0BADF000, 0x70008000
PATH, POOL, SOURCE, OUTPUT = 0x10001000, 0x10002000, 0x10003000, 0x10004000
CONTROL, LUT = 0x10005000, 0x10007000
SCOPE = "Fresh type-0 HDR through native default auxiliary descriptor, processor, IpuSubmit, PrepareCalculations, topology and wrapper creation. Native InstantiatePasses is replayed separately. The FIPLIB geometry/export tail is bypassed when resuming Commit to its task-building entry."
NO_OP = {
    0x801D12F4: "IpuInit",
    0x800D9AC8: "_tx_counter_get",
    0x800D9DF0: "_tx_thread_interrupt_control",
    0x800CDB00: "_tx_mutex_create",
    0x800CBEE4: "_tx_mutex_get",
    0x800D193C: "_tx_mutex_put",
    0x800AD120: "CObservable constructor",
    0x800B6A40: "CObserver constructor",
    0x800AD164: "CObservable::Register",
    0x800A1310: "Fprintf_B",
    0x8009D910: "Timing/diagnostic",
    0x8009BDD8: "TimingMarkIsGroupEnabled",
    0x800213FC: "Configuration byte",
    0x80333E38: "CIpuDriver::GetDriver",
}
ALLOC = {
    0x8000BF28: ("PoolAllocEx", 1),
    0x8000D8BC: ("operator new", 0),
    0x8000D828: ("operator new with alignment", 0),
    0x804F60F4: ("operator new", 0),
    0x80B1F120: ("MemAlloc", 0),
}


def reference():
    return dict(
        analysis_elf_sha256=ELF_SHA256,
        scope=SCOPE,
        stubs={f"0x{a:08x}": name for a, name in {
            **NO_OP, **{a: name for a, (name, _) in ALLOC.items()},
        }.items()},
        execution_boundary=dict(
            auxiliary_constructor_start="0x80b17fec", auxiliary_constructor_stop="0x80b121d8",
            fiplib_analysis_tail_skipped_at="0x8017cfd0",
            commit_resumed_at="0x8033ad88", commit_stopped_at="0x80339040",
        ),
        limitations=[
            "Synthetic 64 by 16 buffers and gamma LUT. The default auxiliary descriptor and its tables are constructed from original firmware instructions.",
            "Allocation, RTOS, diagnostics and driver access are modeled. Task construction, TranslateFilters and Go are outside this replay.",
        ],
        result=dict(
            processor_param_4=0, processor_mode=0, cbc_mode=0,
            image_input_type=6, image_output_type=8,
            fiplib_input_format=13, fiplib_output_format=1, category=0,
            fiplib_phase=0, topology_level=1, topology_locations=[0, 6, 10, 5], wrapper_kinds=[0]*4,
            pass_count=4, pass_vtables=["0x8051f158", "0x8051d590", "0x8051f0b8", "0x8051ed00"],
            top_controls=["0x8017bc80", "0x80171758", "0x80177468", "0x801788b0"],
            S=0, D=0, Q=0, T=[1, 1, 0, 1], start=0, end_exclusive=4,
        ),
    )


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

    class Allocate(angr.SimProcedure):
        def run(self, a0, a1, *, size_arg):
            size = concrete(self.state, (a0, a1)[size_arg])
            assert 0 < size <= 0x8000
            if size == 0xB40:
                address = PATH
            else:
                index = self.state.globals.get("allocation_count", 0)
                self.state.globals["allocation_count"] = index + 1
                address = 0x12000000 + index * 0x8000
            self.state.memory.store(address, bytes(size))
            return address

    for address in NO_OP:
        project.hook(address, NoOp())
    for address, (_, size_arg) in ALLOC.items():
        project.hook(address, Allocate(size_arg=size_arg))

    def advance(state, find):

        sim = project.factory.simgr(state)
        sim.explore(find=find, n=4096)
        if len(sim.found) != 1 or sim.active or sim.errored:
            last = [(hex(s.addr), s.history.jumpkind) for s in sim.deadended + sim.unconstrained]
            errors = [(hex(item.state.addr), str(item.error)) for item in sim.errored]
            raise RuntimeError(f"Replay failed at {state.addr:#x}: {sim}. {errors}; {last}")
        return sim.found[0]

    def call(state, pc, args, stop=RETURN):
        state.regs.pc, state.regs.ra = pc, RETURN
        for index, value in enumerate(args):
            setattr(state.regs, f"a{index}", value)
        return advance(state, stop)

    state = project.factory.blank_state(addr=0x801BCEFC, add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.memory.store(STACK - 0x4000, bytes(0x5000))
    state.regs.sp = STACK
    state.memory.store(POOL, bytes(0x40))

    state.memory.store(0x801E3824, bytes(0x68))
    state.memory.store(0x80358050, bytes(4))
    state.memory.store(0x801B0604, struct.pack("<I", 0x10008000))
    state.memory.store(0x10008000, bytes(16))
    state = call(state, 0x801BCEFC, [POOL])
    state = call(state, 0x8017C82C, [])
    for address, buffer in ((SOURCE, 0x20003000), (OUTPUT, 0x20004000)):
        state.memory.store(address, struct.pack("<7I", buffer, 64, 16, 0, 0, 64, 16))
    # Enter the default auxiliary-descriptor construction arm and stop
    # before the caller-specific HdrGetContext publishes the allocated object.
    state = call(state, 0x80B17FEC, [], 0x80B121D8)
    aux = concrete(state, state.regs.s0)
    assert [read(state, aux+off) for off in (0,4,8)] == [0x1060,0x1F,0xC]
    assert read(state, aux+0x105C,2) == 0xA0
    state.memory.store(CONTROL, struct.pack("<4I", 0, 0, LUT, aux))
    state.memory.store(LUT, bytes(0x400))
    state = call(state, 0x80B1C104, [SOURCE, OUTPUT, 0x0F01, CONTROL], 0x8033A7B8)
    processor = concrete(state, state.regs.a0)
    assert processor == read(state, PATH + 0x880)
    observed = dict(
        processor_param_4=read(state, processor+0x26C),
        processor_mode=read(state, processor+0x284),
        cbc_mode=read(state, processor+0x288),
        image_input_type=read(state, read(state, processor+0x10)+0x68),
        image_output_type=read(state, read(state, processor+0x18)+0x68),
    )
    state = advance(state, 0x8017C9F8)
    fip_inputs = concrete(state, state.regs.a0)
    observed.update(fiplib_input_format=read(state,fip_inputs+6,1), fiplib_output_format=read(state,fip_inputs+7,1),
                    category=read(state,fip_inputs+9,1), fiplib_phase=read(state,fip_inputs+0x1738,1))
    observed.update(S=read(state,fip_inputs+1,1), D=read(state,fip_inputs+0x1072,1),
                    Q=read(state,fip_inputs+9,1))
    preserved = {reg: getattr(state.regs, reg) for reg in
                 ("sp", "ra", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "fp")}
    state = advance(state, 0x8017CFD0)
    fiplib = read(state, 0x801B0610)
    output = read(state, processor+0x40)
    count = read(state, output)
    assert count == 4
    wrapper_array = read(state, output+4)
    observed.update(
        topology_level=read(state, fiplib+0xCC, 1),
        topology_locations=[read(state, fiplib+0x88+4*i) for i in range(count)],
        wrapper_kinds=[read(state, wrapper_array+0x24*i+0x14) for i in range(count)],
        pass_count=count,
    )
    active = read(state, 0x801B0604)
    instantiated = call(state.copy(), 0x8017AF94, [fiplib, active])
    vtables = [read(instantiated, read(instantiated, fiplib+4*i)) for i in range(count)]
    topology = [read(state, fiplib+0x44+4*i) for i in range(count)]
    observed.update(
        pass_vtables=[hex(v) for v in vtables],
        top_controls=[hex(read(instantiated, v+0x24)) for v in vtables],
        T=[read(state, read(state, address+0x88)) for address in topology],
    )

    # Restore the caller state at the modeled FIPLIB return boundary. The
    # original count and wrapper allocation remain in the state's memory.
    for reg, value in preserved.items():
        setattr(state.regs, reg, value)
    assert concrete(state, state.regs.ra) == 0x8033AD88
    state.regs.pc = state.regs.ra
    state = advance(state, 0x80339040)
    observed.update(start=read(state,processor+0x30C), end_exclusive=read(state,processor+0x310))
    expected = reference()
    assert observed == expected["result"], observed
    return expected


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
    print("Fresh HDR topology and Commit range PASS")


if __name__ == "__main__":
    main()
