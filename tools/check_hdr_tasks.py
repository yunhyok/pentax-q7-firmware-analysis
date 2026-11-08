"""Replay fresh Q7 HDR C12 task construction and direct queue handoff."""
import argparse
import json
import struct
from pathlib import Path
from check_isp_registers import ELF_SHA256, load_project

from check_submit_choice import ELF_SHA256

RETURN, STACK = 0x0BADF000, 0x70008000
PATH, POOL, SOURCE, OUTPUT = 0x10001000, 0x10002000, 0x10003000, 0x10004000
CONTROL, LUT = 0x10005000, 0x10007000
DRIVER = 0x10009000
PROCESSOR_FIELDS = {'0x2f0': 1, '0x314': 0, '0x310': 4, '0x370': 0}
TASK_FIELDS = [{'0x220': 0, '0x224': 1, '0x228': 0, '0x234': 0, '0x298': 3} for _ in range(4)]
DRIVER_FIELDS = {'0x344': 0, '0x348': 4, '0x34c': 0, '0x340': 0}
FC1 = [{'uid': 9, 'enabled': 0, 'flags': 0}, {'uid': 35, 'enabled': 1, 'flags': 0}, {'uid': 61, 'enabled': 0, 'flags': 0}, {'uid': 87, 'enabled': 1, 'flags': 0}]
SCOPE = ("Original default HDR auxiliary descriptor through IpuToneMapRgb, FIPLIB geometry/export, "
         "CalculateTopology, TranslateFilters and virtual task Commit. Processor Go then executes "
         "to the modeled ThreadX queue sender.")
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
    0x8009D910: "TimingMarkF",
    0x8009BDD8: "TimingMarkIsGroupEnabled",
    0x800213FC: "SmdbIsZLightEnabled returns 0",
    0x8000C598: "PoolFreeEx",
    0x8000D8E8: "operator delete with diagnostics",
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
            **NO_OP,
            **{a: name for a, (name, _) in ALLOC.items()},
            0x80333E38: "CIpuDriver::GetDriver returns modeled driver",
            0x800D7C04: "_tx_queue_send records message and returns success",
            0x800D6AA4: "OsSysHaltEx fails replay if reached",
            0x800A2180: "__assfail fails replay if reached",
        }.items()},
        limitations=[
            "The fixture uses 512 by 128 buffers, a synthetic gamma LUT, the native default HDR auxiliary descriptor, and the modeled configuration bit in the stub list.",
            "Processor Go is invoked on the same committed processor. PathGo's external synchronization, RTOS queue processing, driver RunTask and camera hardware are outside the replay.",
            "The allocator provides distinct RAM blocks and ignores frees. No task or exported wrapper is injected.",
        ],
        result=dict(
            wrapper_kinds=[0, 0, 0, 0],
            topology_locations=[0, 6, 10, 5],
            create_indices=[0, 1, 2, 3],
            task_ids=[0, 1, 2, 3],
            task_vtables=["0x804ff1e0"]*4,
            observer_vtables=["0x804ff228"]*4,
            final_flags=[0, 0, 0, 1],
            committed_ids=[0, 1, 2, 3],
            queue_task_ids=[0, 1, 2, 3],
            queue="driver+0x224",
            queue_wait=0,
            processor_fields=PROCESSOR_FIELDS,
            task_fields=TASK_FIELDS,
            driver_fields=DRIVER_FIELDS,
            fc1=FC1,
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

    class Driver(angr.SimProcedure):
        def run(self):
            return DRIVER

    class Halt(angr.SimProcedure):
        def run(self, message):
            address = concrete(self.state, message)
            raise RuntimeError(f"Firmware halt at {concrete(self.state,self.state.regs.ra):#x}: {self.state.solver.eval(self.state.memory.load(address,70),cast_to=bytes)!r}")

    class Allocate(angr.SimProcedure):
        def run(self, a0, a1, *, size_arg):
            size = concrete(self.state, (a0, a1)[size_arg])
            assert 0 < size <= 0x800000
            if size == 0xB40:
                address = PATH
            else:
                index = self.state.globals.get("allocation_count", 0)
                self.state.globals["allocation_count"] = index + 1
                address = 0x12000000 + index * 0x800000
            self.state.memory.store(address, bytes(min(size, 0x8000)))
            return address

    for address in NO_OP:
        project.hook(address, NoOp())
    for address, (_, size_arg) in ALLOC.items():
        project.hook(address, Allocate(size_arg=size_arg))

    class QueueSend(angr.SimProcedure):
        def run(self, queue, message, wait):
            task = read(self.state, concrete(self.state, message))
            observe(self.state, "queue", (concrete(self.state, queue), concrete(self.state, wait), task, read(self.state, task+0x2A0)))
            return 0

    def observe(state, key, value):
        state.globals[key] = state.globals.get(key, ()) + (value,)

    def record_create(state):
        sp = concrete(state,state.regs.sp)
        value = (read(state,sp+0x14), read(state,sp+0x18))
        observe(state,"created", value)

    def record_final_flag(state):
        sp = concrete(state,state.regs.sp)
        observe(state,"translated", (read(state,sp+0xAC), concrete(state,state.regs.fp)))

    def record_commit(state):
        task = concrete(state,state.regs.a0)
        value = (task, read(state,task+0x2A0))
        observe(state,"committed", value)

    for address, recorder in ((0x80345850,record_create),(0x8033949C,record_final_flag),(0x8035572C,record_commit)):
        project.hook(address, recorder, length=0)
    project.hook(0x800D7C04, QueueSend())
    project.hook(0x80333E38, Driver())
    project.hook(0x800D6AA4, Halt())
    project.hook(0x800A2180, Halt())

    def advance(state, find):
        sim = project.factory.simgr(state)
        sim.explore(find=find, n=65536)
        if len(sim.found) != 1 or sim.active or sim.errored:
            last = [(hex(s.addr), s.history.jumpkind) for s in sim.deadended + sim.unconstrained + sim.active]
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
    state.memory.store(DRIVER, bytes(0x400))
    state.memory.store(0x801E3824, bytes(0x68))
    state.memory.store(0x80358050, bytes(4))
    state.memory.store(0x801B0604, struct.pack("<I", 0x10008000))
    state.memory.store(0x10008000, bytes(16))
    state = call(state, 0x801BCEFC, [POOL])
    state = call(state, 0x8017C82C, [])
    for address, buffer in ((SOURCE, 0x20003000), (OUTPUT, 0x20004000)):
        state.memory.store(address, struct.pack("<7I", buffer, 512, 128, 0, 0, 512, 128))
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
    assert [read(state, processor+off) for off in (0x26C, 0x284, 0x288)] == [0, 0, 0]
    state = advance(state, 0x80339040)
    fiplib = read(state, 0x801B0610)
    output = read(state, processor+0x40)
    count = read(state, output)
    assert count == 4
    assert [read(state, processor+off) for off in (0x30C, 0x310)] == [0, count]
    wrappers = read(state, output+4)
    wrapper_kinds = [read(state, wrappers+0x24*i+0x14) for i in range(count)]
    locations = [read(state, fiplib+0x88+4*i) for i in range(count)]

    state = advance(state, 0x80339350)
    tasks = [read(state, processor+0x204+4*i) for i in range(count)]
    assert all(tasks) and len(set(tasks)) == count
    assert all(read(state, task+0x1C8) == DRIVER for task in tasks)
    state = advance(state, 0x8035572C)
    state = advance(state, 0x801D0FCC)
    assert [read(state, processor+0x204+4*i) for i in range(count)] == tasks
    assert all(read(state, task+0x1BC) for task in tasks)
    processor_fields = {hex(off): read(state, processor+off) for off in (0x2F0, 0x314, 0x310)}
    processor_fields["0x370"] = read(state, processor+0x370, 1)
    task_fields = [{hex(off): read(state, task+off) for off in (0x220, 0x224, 0x228, 0x234, 0x298)}
                   for task in tasks]
    task_ids = [read(state, task+0x2A0) for task in tasks]
    created = state.globals["created"]
    translated = state.globals["translated"]
    committed = state.globals["committed"]
    assert [n for _, n in created] == [count]*count
    assert [i for i, _ in translated] == list(range(count))
    assert [task for task, _ in committed] == tasks

    filters = [read(state,read(state,read(state,task+0x1BC)+4)+13*4) for task in tasks]
    fc1 = [dict(uid=read(state,flt+0x2C), enabled=read(state,flt+0x28,1), flags=read(state,flt+0x48)) if flt else None
           for flt in filters]
    assert all(not flt or read(state,flt)==0x804FF9F0 for flt in filters)
    state = call(state, 0x80338BCC, [processor])
    driver_fields = {hex(off): read(state,DRIVER+off) for off in (0x344,0x348,0x34C)}
    driver_fields["0x340"] = read(state,DRIVER+0x340,1)
    messages = state.globals["queue"]
    assert [(queue, wait, task) for queue, wait, task, _ in messages] == [
        (DRIVER+0x224, 0, task) for task in tasks
    ]
    observed = dict(
        wrapper_kinds=wrapper_kinds, topology_locations=locations,
        create_indices=[i for i, _ in created], task_ids=task_ids,
        task_vtables=[hex(read(state, task)) for task in tasks],
        observer_vtables=[hex(read(state, task+8)) for task in tasks],
        final_flags=[flag for _, flag in translated],
        committed_ids=[task_id for _, task_id in committed],
        queue_task_ids=[task_id for _, _, _, task_id in messages],
        queue="driver+0x224", queue_wait=0,
        processor_fields=processor_fields, task_fields=task_fields, driver_fields=driver_fields, fc1=fc1,
    )
    expected = reference()
    assert observed == expected["result"], observed
    return {**expected, "result": observed}

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
    print("Fresh HDR creation, final flag, Commit and queue order PASS")


if __name__ == "__main__":
    main()
