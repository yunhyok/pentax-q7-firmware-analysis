"""Replay Q7 E3 Color Space menu transitions using original MIPS code."""
import argparse
import json
from os.path import lexists
from pathlib import Path

from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project


SETTING, BACKUP = 0x8153CA43, 0x80BED850
FOCUS, CANVAS, BUILD_FLAG = 0x80B63168, 0x80B6316C, 0x80B63170
E3_FOCUS, CAPTURE_REQUEST = 0x80B62F24, 0x80BEC670
UI_ROOT, UI_RUNNING = 0x80C7E7E4, 0x80C7E7E8
PARENT, MODE, SETTING_ID = 0x23, 0x53, 0xD7
WIDGET = (0x0191D001, 0x0191D002)
CASE_SPECS = (
    ("srgb-to-adobergb-confirm", 0, 1, 8),
    ("adobergb-to-srgb-confirm", 1, 0, 8),
    ("srgb-to-adobergb-cancel", 0, 1, 3),
    ("adobergb-to-srgb-cancel", 1, 0, 3),
    ("srgb-same-value-confirm", 0, 0, 8),
    ("adobergb-same-value-confirm", 1, 1, 8),
)
MODELED = {
    "0x800ee804": "Allocate zeroed synthetic GUI heap at the requested size.",
    "0x80433354": "Bypass mode-entry DataHelper_UpdateUserData / arrange-mode display update. This call's effects are outside the replay.",
    "0x80adfeb8": "Accept UI service queue requests. The harness performs the original root activation explicitly.",
    "0x80125c24": "Accept the UI start wakeup without an RTOS thread.",
    "0x809dc650": "Accept capture-thread notification. For mode requests the harness observes the original record and clears it as the receiver would consume it.",
    "0x809dc714": "Record the event-3 CaptureMode quit request without running the full capture-mode teardown.",
    "0x8024df84": "Observe DCF API boundary after the original prefix-selection routines, without touching media.",
    "0x80adf240": "Model external UI stop by clearing the root and running flag. The harness deactivates the original widget tree before the original mode-end callback.",
}
SCOPE = ("Original E3 switch handler at a focused row, capture mode registration/entry, widget construction, "
         "canvas activation/key dispatch/focus, mode confirm/cancel, and real menu getter/setter instructions "
         "against synthetic RAM. Queue reception, display/update and hardware boundaries are modeled.")


def expected_step(action, getter, backup, focus, setter=None, dcf=None, request=None,
                  key=None, consumed=None):
    return dict(action=action, key=key, gui_consumed=consumed, getter=getter, backup=backup,
                focused_widget=None if focus is None else WIDGET[focus],
                setter_calls=[] if setter is None else [[SETTING_ID, setter]],
                setting_byte_stores=[] if setter is None else [[SETTING, 1, setter]],
                dcf_modes=[] if dcf is None else [dcf], mode_request=request)


def reference():
    cases = []
    for name, initial, selection, terminal_key in CASE_SPECS:
        changed = selection != initial
        cancel = terminal_key == 3
        final = initial if cancel else selection
        steps = [expected_step("open", initial, initial, initial, initial, initial,
                               [MODE, 1, 12, 0, 0])]
        if changed:
            steps.append(expected_step("choose", selection, initial, selection, selection,
                                       selection, key=10 if selection else 9, consumed=True))
        steps += [
            expected_step("cancel" if cancel else "confirm", final, initial, selection,
                          initial if cancel else None,
                          request=["quit", 1] if cancel else [PARENT, 1, 8, 0, 0],
                          key=terminal_key, consumed=False),
            expected_step("close", final, initial, None),
            expected_step("reopen", final, final, final, final, final, [MODE, 1, 12, 0, 0]),
        ]
        cases.append(dict(case=name, initial=initial, selected=selection, steps=steps))
    return dict(analysis_elf_sha256=ELF_SHA256, scope=SCOPE, modeled_boundaries=MODELED,
                cases=cases, case_count=len(cases),
                setter_call_count=sum(len(step["setter_calls"]) for c in cases for step in c["steps"]),
                setting_byte_store_count=sum(len(step["setting_byte_stores"]) for c in cases for step in c["steps"]))


def validate_report(report):
    """Validate public replay metadata without a firmware image or angr."""
    engine = report.get("engine")
    if not isinstance(engine, str) or not engine.startswith("angr ") or not engine.endswith(" / VEX"):
        raise ValueError("invalid Color Space replay engine")
    if report != dict(reference(), engine=engine):
        raise ValueError("Color Space replay report differs from the reference transitions")


def concrete(state, value):
    if isinstance(value, int):
        return value
    assert not value.symbolic, (hex(state.addr), value)
    return state.solver.eval(value)


def put(state, address, value, size=4):
    state.memory.store(address, value.to_bytes(size, "little"))


def get(state, address, size=4):
    return concrete(state, state.memory.load(address, size, endness="Iend_LE"))


def record(state, key, event):
    state.globals[key] = (*state.globals.get(key, ()), event)


def call(project, state, address, *args):
    state.regs.pc, state.regs.ra = address, RETURN_PC
    for index, value in enumerate((*args, 0, 0, 0, 0)[:4]):
        setattr(state.regs, f"a{index}", value)
    sim = project.factory.simgr(state, save_unconstrained=True)
    sim.explore(find=RETURN_PC, n=5000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, (
        hex(address), sim.errored, [str(s.regs.pc) for s in sim.active + sim.unconstrained])
    state = sim.found[0]
    assert concrete(state, state.regs.sp) == STACK_TOP
    return state, concrete(state, state.regs.v0)


def install_hooks(project, angr):
    class Allocate(angr.SimProcedure):
        def run(self, pool, size, source_file, line):
            size = concrete(self.state, size)
            address = self.state.globals.get("heap", 0x10002000)
            assert 0 < size < 0x1000 and address + size < 0x10010000
            self.state.globals["heap"] = (address + size + 15) & ~15
            self.state.memory.store(address, bytes(size))
            return address

    class Accept(angr.SimProcedure):
        def run(self):
            return 0

    class Quit(angr.SimProcedure):
        def run(self, reason):
            record(self.state, "quit", concrete(self.state, reason))
            return 0

    class Media(angr.SimProcedure):
        def run(self, selector, count, address):
            assert (concrete(self.state, selector), concrete(self.state, count)) == (0, 4)
            record(self.state, "dcf", get(self.state, 0x80444E6B, 1))
            return 0

    class Stop(angr.SimProcedure):
        def run(self):
            put(self.state, UI_RUNNING, 0, 1)
            put(self.state, UI_ROOT, 0)
            return 1

    for address in (0x80433354, 0x80ADFEB8, 0x80125C24, 0x809DC650):
        project.hook(address, Accept())
    project.hook(0x800EE804, Allocate())
    project.hook(0x809DC714, Quit())
    project.hook(0x8024DF84, Media())
    project.hook(0x80ADF240, Stop())


def prepare(project, angr):
    state = project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp = STACK_TOP
    for start, size in ((STACK_TOP - 0x1000, 0x1100), (0x80BEC400, 0x5000),
                        (0x80C7E000, 0x1000), (0x8153C000, 0x1000), (0x10000000, 0x1000)):
        state.memory.store(start, bytes(size))
    state, _ = call(project, state, 0x80A8784C)               # capture modes and callbacks
    state, _ = call(project, state, 0x80AC9024, 0x809BD04C)   # original GUI event listener table
    state, _ = call(project, state, 0x80A847E0)               # real color-space widget construction
    assert get(state, BUILD_FLAG, 1) == 1
    root = get(state, CANVAS)
    assert get(state, root + 4) == 0x0191D000
    for widget in (*WIDGET, 0x0191D005, 0x0191D00B, 0x0191D010, 0x0191D014, 0x0191D019):
        state, component = call(project, state, 0x80AC8718, widget, root)
        assert get(state, component + 4) == widget
    return state


def replay_case(project, state, angr, spec):
    name, initial, selection, terminal_key = spec
    guard = bytes(range(16))
    state.memory.store(SETTING - 8, guard)
    put(state, SETTING, initial, 1)
    steps = []

    def observe_setter(state):
        record(state, "setters", [concrete(state, state.regs.a0), concrete(state, state.regs.a1)])

    def observe_store(state):
        record(state, "stores", [SETTING, concrete(state, state.inspect.mem_write_length),
                                 concrete(state, state.inspect.mem_write_expr)])

    state.inspect.b("instruction", when=angr.BP_BEFORE, instruction=0x80430D08, action=observe_setter)
    state.inspect.b("mem_write", when=angr.BP_BEFORE, mem_write_address=SETTING, action=observe_store)

    def request():
        if state.globals.get("quit"):
            return ["quit", *state.globals["quit"]]
        if get(state, CAPTURE_REQUEST):
            result = [get(state, CAPTURE_REQUEST + i * 4) for i in range(5)]
            put(state, CAPTURE_REQUEST, 0)
            return result
        return None

    def snapshot(action, *, key=None, consumed=None, closed=False, queued=None):
        nonlocal state
        state, getter = call(project, state, 0x8043374C)
        assert getter == get(state, SETTING, 1)
        around = state.solver.eval(state.memory.load(SETTING - 8, len(guard)), cast_to=bytes)
        assert around[:8] == guard[:8] and around[9:] == guard[9:]
        steps.append(dict(action=action, key=key, gui_consumed=consumed, getter=getter,
                          backup=get(state, BACKUP, 1),
                          focused_widget=None if closed else get(state, FOCUS),
                          setter_calls=list(state.globals.pop("setters", ())),
                          setting_byte_stores=list(state.globals.pop("stores", ())),
                          dcf_modes=list(state.globals.pop("dcf", ())), mode_request=queued))
        state.globals.pop("quit", None)

    def open_mode(action):
        nonlocal state
        put(state, E3_FOCUS, 0x01B29002)
        state, _ = call(project, state, 0x80A438F4, 12)
        queued = request()
        assert queued == [MODE, 1, 12, 0, 0]
        state, _ = call(project, state, 0x80A8BA08, 0x10000000, queued[0])
        root = get(state, CANVAS)
        assert get(state, UI_ROOT) == root
        state, _ = call(project, state, 0x80AC9050, 0xFFFF)
        state, _ = call(project, state, 0x80AC8524, root)
        snapshot(action, queued=queued)

    def switch(key):
        nonlocal state
        state, consumed = call(project, state, 0x80AC8594, key, get(state, CANVAS))
        if not consumed:
            state, _ = call(project, state, 0x80A8BFA8, key)
        return bool(consumed)

    open_mode("open")
    if selection != initial:
        key = 10 if selection else 9
        consumed = switch(key)
        snapshot("choose", key=key, consumed=consumed, queued=request())
    consumed = switch(terminal_key)
    snapshot("confirm" if terminal_key == 8 else "cancel", key=terminal_key,
             consumed=consumed, queued=request())
    state, _ = call(project, state, 0x80AC855C, get(state, CANVAS))
    state, _ = call(project, state, 0x80A84EDC)
    assert get(state, UI_ROOT) == 0 and get(state, UI_RUNNING, 1) == 0
    snapshot("close", closed=True)
    open_mode("reopen")
    return dict(case=name, initial=initial, selected=selection, steps=steps)


def replay(elf):
    project = load_project(elf)
    import angr

    install_hooks(project, angr)
    base = prepare(project, angr)
    cases = []
    for spec, expected in zip(CASE_SPECS, reference()["cases"], strict=True):
        observed = replay_case(project, base.copy(), angr, spec)
        for actual_step, expected_step in zip(observed["steps"], expected["steps"], strict=True):
            assert actual_step == expected_step, (spec[0], actual_step, expected_step)
        cases.append(observed)
    report = dict(reference(), cases=cases, engine=f"angr {angr.__version__} / VEX")
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if lexists(args.output):
        parser.error("output must not exist")
    report = replay(args.elf)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(f"PASS {report['case_count']} cases, {report['setter_call_count']} setter calls, "
          f"{report['setting_byte_store_count']} native setting-byte stores")


if __name__ == "__main__":
    main()
