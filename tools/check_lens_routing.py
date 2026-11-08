"""Replay the Q7 AF callback and focus dispatch to the lens API boundary."""
import argparse
import json
from pathlib import Path


from check_isp_registers import ELF_SHA256, load_project
ELF_SIZE = 12504100
CALLBACK_SLOT = 0x80c17e00
RECIPIENT = 0x8040a008
FOCUS_INFO = 0x80c6aad4
FOCUS_DISPATCH = 0x8042e040
SEND_QUEUE = 0x80116af8
LENS_COMMUNICATION = 0x80111214


def require(condition, message):
    if not condition:
        raise ValueError(message)


def replay(elf):
    import angr

    project = load_project(elf)
    options = {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
               angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    endness = project.arch.memory_endness
    return_address = 0x0badf000

    def until(state, target):
        sim = project.factory.simgr(state)
        sim.explore(find=target, n=256)
        require(len(sim.found) == 1 and not sim.errored and not sim.active,
                f"incomplete replay from {state.addr:#x} to {target:#x}: {sim}")
        return sim.found[0]

    def value(state, expression):
        require(not expression.symbolic, "replay produced a symbolic value")
        return state.solver.eval(expression)

    def load(state, address, size=4):
        return value(state, state.memory.load(address, size, endness=endness))

    def store(state, address, data, size=4):
        state.memory.store(address, data, size=size, endness=endness)

    def blank(address):
        state = project.factory.blank_state(addr=address, add_options=options)
        state.regs.sp = 0x7fff0000
        state.regs.ra = return_address
        return state

    # Stop on entry to the next getter, after its JAL delay slot stores the pointer.
    bound = until(blank(0x8037e13c), 0x8040cc6c)
    recipient = load(bound, CALLBACK_SLOT)
    require(recipient == RECIPIENT, "unexpected AF callback binding")

    cases = []
    for mode, entry, message, command, payload in (
        (0, 0x801134a4, 6, 4, b"\x12\x34\x56"),
        (1, 0x80113634, 8, 6, b"\0"),
        (2, 0x8011357c, 7, 3, b"\x12\x34\x56\x78\x34\x56"),
        (3, 0x8011355c, 2, 4, b"\x12\x34\x56"),
    ):
        state = project.factory.call_state(
            0x8037eb78, mode, 1, 0x12, 0x3456, 0x12345678,
            ret_addr=return_address, prototype="void f(int, int, int, int, int)",
            add_options=options)
        store(state, CALLBACK_SLOT, recipient)
        state = until(state, recipient)
        callback_args = [value(state, state.regs.a0), value(state, state.regs.a1)]
        require(callback_args == [0x6003c, 0], f"mode {mode}: callback arguments differ")
        fields = [load(state, FOCUS_INFO + off, size)
                  for off, size in ((0, 1), (1, 1), (2, 1), (4, 2), (8, 4))]
        require(fields == [mode, 1, 0x12, 0x3456, 0x12345678],
                f"mode {mode}: focus-control fields differ")
        state = until(until(state, FOCUS_DISPATCH), entry)
        if mode == 3:
            state = until(state, 0x8042e12c)
            require(load(state, 0x80c2aa48, 1) == 1, "VD-sync search did not set its pending flag")
        else:
            store(state, 0x80c2a2e2, 0, 1)  # Allow actuator drive.
            state = until(state, SEND_QUEUE)
            require(value(state, state.regs.a0) == message, f"mode {mode}: queue command differs")

        # Resume after the worker receives the message and waits for prior lens I/O.
        worker = blank(0x801169cc)
        worker.regs.s0 = message
        worker.regs.s2 = 0x8011f0a8
        for address, size in ((0x80c2aa48, 1), (0x80c2aa49, 1), (0x80c2aa4a, 1),
                              (0x80c2aa4b, 1), (0x80c2aa4c, 2), (0x80c2aa50, 4),
                              (0x80c2aa54, 2)):
            store(worker, address, load(state, address, size), size)
        if mode == 3:
            # A separate VD-sync event feeds message 2. Skip the prior periodic transaction.
            worker = until(worker, 0x80114700)
            worker.regs.pc = 0x80114754
        worker = until(worker, LENS_COMMUNICATION)
        args = [value(worker, getattr(worker.regs, f"a{i}")) for i in range(4)]
        require(args == [0, 1, 2, command], f"mode {mode}: lens API arguments differ")
        send_buffer = load(worker, value(worker, worker.regs.sp) + 0x10)
        actual = bytes(load(worker, send_buffer + i, 1) for i in range(len(payload)))
        require(actual == payload, f"mode {mode}: caller-local send buffer differs")
        cases.append(dict(
            mode=mode, recipient=f"{recipient:#x}", callback_arguments=callback_args,
            focus_entry=f"{FOCUS_DISPATCH:#x}", mode_entry=f"{entry:#x}",
            queue_message=message, message_source="independent VD-sync trigger" if mode == 3 else "mode branch",
            lens_communication_arguments=args, local_payload_hex=actual.hex()))
    return dict(engine=f"angr {angr.__version__} / VEX",
                binding_case=dict(start="0x8037e13c", stop="0x8040cc6c",
                                  pointer=f"{CALLBACK_SLOT:#x}", value=f"{recipient:#x}"),
                cases=cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, help="the synthetic Q7 v1.01 analysis ELF")
    parser.add_argument("--output", required=True, type=Path, help="new replay evidence JSON")
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output must not exist")
    try:
        report = replay(args.elf)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    print(f"AF callback binding and {len(report['cases'])} focus-mode replays passed")


if __name__ == "__main__":
    main()
