"""Replay the Q7 lens readiness, response-cache and reset boundaries on synthetic RAM."""
import argparse
import json
from pathlib import Path

from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project
from check_lens_policy import (COMM_STATE, DEST, GROUPS, OPERATIONS, PLC_SPEC, PLC_SPEC_OK,
                               PLC_STD, PLC_STD_OK, RX, VDRC, VD_OK, get, make_state, put)


INIT, RESET, POWER_OFF, BOOTSTRAP = 0x8011097C, 0x8010F598, 0x8010FA10, 0x80111448
LINK, TRANSPORT, AF_GET = 0x80110C50, 0x80111214, 0x80114B08
PRIMARY, SINGLE, VD_SYNC = 0x80113EAC, 0x80115F50, 0x80115C8C
DETECT, MOUNT_SWITCH = 0x8011045C, 0x80110B34
MAP_READY, TX, LATCH = 0x80C2A2D9, 0x80C29EC8, 0x80C25E76
AF_OP = OPERATIONS + 2*256 + 4
FIRST_VD, SECOND_VD = VDRC + 0x100, VDRC + 0x200
GROUP_MAP, SEARCH, REGULAR = (0, 1, 0, 1), (0, 1, 2, 4), (0, 1, 1, 12)
PRIMARY_COMMANDS = ((0, 1, 8, 2), (0, 1, 8, 11), (0, 1, 8, 21),
                    (0, 1, 3, 5), (0, 1, 3, 6), (0, 1, 4, 8))
MECHANICAL = (0, 1, 8, 1)
OP_MAP = {1: (12,), 2: (4,), 3: (5, 6), 4: (8,), 8: (1, 2, 11, 21)}
INIT_CASES = ("success", "regular-map-denied", "regular-reply-fails", "primary-spec-fails",
              "search-map-denied", "partial-map-fails", "already-powered")
CACHE_CASES = ("single-failed-reply", "vd-sync-failed-reply", "vd-sync-failed-prefix",
               "primary-refresh-failed")
RESET_CASES = ("control-reset", "mount-switch-open", "detect-with-latch", "detect-without-latch")
POWERED_BYTE, STALE_COMM = 1, 0x6F
FRESH_POSITION, FAILED_POSITION, TAIL = 0x11223344, 0x55667788, 0xDECAFBAD
SPEC_ID, STD_LIMIT = 0x1234, 0x01020304
NOOPS = {
    0x8010F344: "low-level sequence/port setup",
    0x801168B8: "semaphore/worker control",
    0x80105E44: "interrupt line disable",
    0x8010F7C0: "mount BtoL pin control",
    0x8010F8E4: "serial configuration",
    0x8010FD10: "link frequency setup, returns 0",
    0x8010F4F0: "delay",
    0x80116974: "lens worker queue clear",
    0x8010F77C: "mount MoVd pin control",
    0x8010F808: "lens port configuration",
    0x80111C9C: "tube-closed notification recipient",
    0x801102E0: "mount-switch power control",
    0x8011689C: "mount timer scheduling",
    0x80105E10: "interrupt line enable",
}
MODELS = {
    0x80110894: "synthetic power-enable input",
    0x8010F78C: "record power-enable request without GPIO",
    0x8011090C: "synthetic power-on check succeeds",
    0x80110348: "synthetic mount-detect pin",
    0x8011032C: "synthetic mount-switch pin",
    0x80116AF8: "record retry queue message",
    0x80111354: "LLC command statuses and receive bytes",
    LINK: "serial response/status injection below original transport admission",
    0x8011EBAC: "fixed body temperature 25",
}
TIMEOUT_MODELS = {
    0x801102F4: "BtoL input low", 0x801104C4: "LtoB input low",
    0x801168AC: "synthetic ready-to-communicate result 1",
    0x8010824C: "timer setup no-op", 0x80108278: "timer start no-op",
    0x80108444: "timer cleanup no-op", 0x801081F4: "timer stop no-op",
    0x80125BE0: "supply event mask 0x100 at the wait boundary",
    INIT: "record recovery reentry and its input state; stop nested initialization",
}


def read(state, address, length):
    expr = state.memory.load(address, length, inspect=False)
    assert not expr.symbolic, hex(address)
    return state.solver.eval(expr, cast_to=bytes)


def num(state, value):
    if isinstance(value, int):
        return value
    assert not value.symbolic
    return state.solver.eval(value)


def record(state, key, event):
    state.globals[key] = (*state.globals.get(key, ()), event)


def call(project, state, entry, *args):
    state.regs.pc, state.regs.ra = entry, RETURN_PC
    for i, value in enumerate((args + (0,)*4)[:4]):
        setattr(state.regs, f"a{i}", value)
    for i, value in enumerate(args[4:], start=4):
        put(state, STACK_TOP+4*i, value)
    sim = project.factory.simgr(state, save_unconstrained=True)
    sim.explore(find=RETURN_PC, n=14000)
    assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, (hex(entry), sim, sim.errored)
    state = sim.found[0]
    assert num(state, state.regs.sp) == STACK_TOP
    return state, num(state, state.regs.v0)


def seed(project, angr):
    state = make_state(project, angr)
    for a, v in ((COMM_STATE, STALE_COMM), (MAP_READY, 1), (AF_OP, 1),
                 (PLC_SPEC_OK, 1), (PLC_STD_OK, 1), (VD_OK, 1)):
        put(state, a, v, 1)
    for a, length in ((PLC_SPEC, 0xA0), (PLC_STD, 0xA0), (VDRC, 0x100),
                      (FIRST_VD, 0x100), (SECOND_VD, 0x100)):
        state.memory.store(a, b"\xa5"*length)
    return state


def permissions(case):
    return {group: (() if (case, group) in (("regular-map-denied", 1), ("search-map-denied", 2)) else ops)
            for group, ops in OP_MAP.items()}


def install(project, angr):
    class Boundary(angr.SimProcedure):
        def run(self, a0, a1, a2, a3, address=None):
            st = self.state
            name = st.globals.get("case")
            if address == 0x80110894:
                return POWERED_BYTE if name == "already-powered" else 0
            if address == 0x8011090C:
                return 1
            if address == 0x8010F78C:
                record(st, "power", num(st, a0))
            if address == 0x80110348:
                return st.globals.get("detect_pin", 0)
            if address == 0x8011032C:
                return st.globals.get("switch_pin", 0)
            if address == 0x80116AF8:
                record(st, "messages", num(st, a0))
            if address == 0x8011EBAC:
                return 25
            return 0

    class LLC(angr.SimProcedure):
        def run(self, mode, command, send, receive):
            st = self.state
            cmd = num(st, command)
            assert num(st, mode) == 0 and cmd in (1, 2, 4, 5)
            status = 0 if st.globals.get("case") == "partial-map-fails" and st.globals.get("partial_failure") else 1
            if status:
                st.memory.store(num(st, receive), b"\x01" + bytes(15))
            record(st, "llc", [cmd, status])
            return status

    class Link(angr.SimProcedure):
        def run(self, mode, send_count, receive_count):
            st = self.state
            case = st.globals.get("case")
            cmd = tuple(read(st, TX, 4))
            count = num(st, receive_count)
            assert 0 <= count <= 0x202
            status = 1
            body = bytearray(count)
            ops = permissions(case)
            if cmd == GROUP_MAP:
                assert count == 8 and get(st, MAP_READY, 1) == 0
                body[:] = sum(1 << g for g in ops).to_bytes(8, "little")
            elif cmd[:2] == (0, 1) and cmd[3] == 0 and cmd[2] in ops:
                assert count == 32 and get(st, MAP_READY, 1) == 0
                if case == "partial-map-fails" and cmd[2] == 2:
                    assert get(st, OPERATIONS+256+12, 1) == 1
                    st.globals["partial_failure"] = True
                    status = 4
                body[:] = sum(1 << op for op in ops[cmd[2]]).to_bytes(32, "little")
            elif cmd in PRIMARY_COMMANDS:
                if case == "primary-refresh-failed" or (case == "primary-spec-fails" and cmd == PRIMARY_COMMANDS[0]):
                    status = 4
                if cmd == PRIMARY_COMMANDS[0]:
                    body[2:4] = SPEC_ID.to_bytes(2, "big")
                elif cmd == PRIMARY_COMMANDS[1]:
                    body[0x47:0x4B] = STD_LIMIT.to_bytes(4, "big")
            elif cmd == REGULAR:
                assert count == 160
                if case in ("regular-reply-fails", "single-failed-reply", "vd-sync-failed-reply",
                            "vd-sync-failed-prefix"):
                    status = 4
                body[:5] = b"\x02" + FRESH_POSITION.to_bytes(4, "big")
                body[0x7A:0x7E] = TAIL.to_bytes(4, "big")
                if case == "vd-sync-failed-prefix":
                    st.memory.store(RX, b"\x03" + FAILED_POSITION.to_bytes(4, "big"))
            elif cmd == SEARCH:
                assert num(st, send_count) == 3
                status = 1
            else:
                assert cmd == MECHANICAL and count == 0
            if status == 1 and count and cmd != SEARCH:
                st.memory.store(RX, bytes(body))
            record(st, "transport", [*cmd, status])
            return status

    for address in (NOOPS | MODELS):
        if address not in (0x80111354, LINK):
            project.hook(address, Boundary(address=address))
    project.hook(0x80111354, LLC())
    project.hook(LINK, Link())
    return Link


def fields(state):
    return dict(communications_state=get(state, COMM_STATE, 1), map_ready=get(state, MAP_READY, 1),
                search_operation=get(state, AF_OP, 1),
                validity=[get(state, a, 1) for a in (PLC_SPEC_OK, PLC_STD_OK, VD_OK)],
                spec_id=int.from_bytes(read(state, PLC_SPEC+2, 2), "big"),
                standard_limit=int.from_bytes(read(state, PLC_STD+0x47, 4), "big"),
                motion=get(state, VDRC, 1), current=int.from_bytes(read(state, VDRC+1, 4), "big"),
                tail=int.from_bytes(read(state, VDRC+0x7A, 4), "big"),
                vd_buffers_zero=not any(read(state, VDRC, 0x300)))


def observe(project, state):
    sample = state.copy()
    sample.globals["transport"] = ()
    actual = fields(sample)
    sample, af = call(project, sample, AF_GET)
    put(sample, DEST, 0)
    sample, vd_status = call(project, sample, 0x801124C0, DEST)
    assert get(sample, DEST) == actual["current"]
    sample, search = call(project, sample, TRANSPORT, *SEARCH, DEST+0x20, DEST+0x40)
    sent = list(sample.globals["transport"])
    assert not sent or sent == [[*SEARCH, 1]]
    return dict(actual, af_enable=af, position_getter_status=vd_status,
                search_forwarded=bool(sent), search_result=search)


def ref_fields(comm, ready, af_op, validity, spec, std, motion, position, tail, zero):
    af = int(bool(comm & 8 and af_op))
    forwarded = ready != 1 or af_op != 0
    return dict(communications_state=comm, map_ready=ready, search_operation=af_op,
                validity=list(validity), spec_id=spec, standard_limit=std, motion=motion,
                current=position, tail=tail, vd_buffers_zero=zero,
                af_enable=af, position_getter_status=validity[2],
                search_forwarded=forwarded, search_result=1 if forwarded else 7)


def reference():
    stale = ref_fields(STALE_COMM, 1, 1, (1, 1, 1), 0xA5A5, 0xA5A5A5A5, 0xA5, 0xA5A5A5A5, 0xA5A5A5A5, False)
    fresh = ref_fields(0x2F, 1, 1, (1, 1, 1), SPEC_ID, STD_LIMIT, 2, FRESH_POSITION, TAIL, False)
    reset = ref_fields(0, 0, 0, (0, 0, 0), 0, 0, 0, 0, 0, True)
    init = {
        "success": fresh,
        "regular-map-denied": ref_fields(0x0F, 1, 1, (1, 1, 0), SPEC_ID, STD_LIMIT, 0, 0, 0, True),
        "regular-reply-fails": ref_fields(0x07, 1, 1, (1, 1, 0), SPEC_ID, STD_LIMIT, 0, 0, 0, True),
        "primary-spec-fails": ref_fields(0x23, 1, 1, (0, 1, 1), 0, STD_LIMIT, 2, FRESH_POSITION, TAIL, False),
        "search-map-denied": dict(fresh, search_operation=0, af_enable=0, search_forwarded=False, search_result=7),
        "partial-map-fails": reset,
        "already-powered": stale,
    }
    startup = []
    for name in INIT_CASES:
        llc = [[c, 1] for c in (1, 2, 4, 5)]
        transactions = [[*GROUP_MAP, 1]] + [[0, 1, group, 0, 1] for group in OP_MAP]
        primary = [[*cmd, 4 if name == "primary-spec-fails" and cmd == PRIMARY_COMMANDS[0] else 1]
                   for cmd in PRIMARY_COMMANDS]
        regular = [] if name == "regular-map-denied" else [[*REGULAR, 4 if name == "regular-reply-fails" else 1]]
        power, retry = [1], []
        if name == "partial-map-fails":
            transactions = transactions[:3]
            transactions[-1][-1] = 4
            llc += [[1, 0]]*4
            power, retry = [1, 0], [1]
        elif name == "already-powered":
            llc, transactions, power = [], [], []
        else:
            transactions += primary + regular + [[*MECHANICAL, 1]]
        startup.append(dict(case=name, after=init[name], llc=llc, transport=transactions,
                            power_requests=power, retry_messages=retry,
                            early_return_2=name == "already-powered"))
    cache = [
        dict(case=CACHE_CASES[0], after=dict(fresh, motion=0, current=0, tail=0, vd_buffers_zero=True),
             transport=[[*REGULAR, 4]]),
        dict(case=CACHE_CASES[1], after=fresh, transport=[[*REGULAR, 4]]),
        dict(case=CACHE_CASES[2], after=dict(fresh, motion=3, current=FAILED_POSITION), transport=[[*REGULAR, 4]]),
        dict(case=CACHE_CASES[3], after=dict(fresh, spec_id=0, standard_limit=0, validity=[0, 0, 0],
                                            position_getter_status=0),
             transport=[[*cmd, 4] for cmd in PRIMARY_COMMANDS]),
    ]
    resets = [
        dict(case=RESET_CASES[0], after=reset, latch=0, power_requests=[]),
        dict(case=RESET_CASES[1], after=reset, latch=1, power_requests=[0]),
        dict(case=RESET_CASES[2], after=reset, latch=0, power_requests=[0]),
        dict(case=RESET_CASES[3], after=fresh, latch=0, power_requests=[]),
    ]
    timeouts = [
        dict(map_ready_before=0, result=5, after=dict(stale, map_ready=0), recovery_reentry=[]),
        dict(map_ready_before=1, result=5, after=reset, recovery_reentry=[[0, 0, 0]]),
    ]
    return dict(analysis_elf_sha256=ELF_SHA256, startup_cases=startup, cache_cases=cache,
                reset_cases=resets, timeout_cases=timeouts,
                models={hex(a): text for a, text in (NOOPS | MODELS).items()},
                timeout_models={hex(a): text for a, text in TIMEOUT_MODELS.items()})


def check_maps(state, expected):
    group = bytes(int(i in expected) for i in range(64))
    operations = bytearray(0x4000)
    for g, ops in expected.items():
        for op in ops:
            operations[256*g+op] = 1
    assert read(state, GROUPS, len(group)) == group
    assert read(state, OPERATIONS, len(operations)) == operations


def run_timeouts(project, angr, link_class):
    class TimeoutBoundary(angr.SimProcedure):
        def run(self, a0, a1, a2, a3, address=None):
            st = self.state
            if address == 0x801168AC:
                return 1
            if address == 0x80125BE0:
                assert num(st, a1) == 0x11111111 and num(st, a3) == 1
                put(st, num(st, a2), 0x100)
                return 0
            if address == INIT:
                record(st, "recovery", [num(st, a0), get(st, COMM_STATE, 1), get(st, MAP_READY, 1)])
            return 0

    project.unhook(LINK)
    for address in TIMEOUT_MODELS:
        project.hook(address, TimeoutBoundary(address=address))
    results = []
    for ready in (0, 1):
        state = seed(project, angr)
        put(state, MAP_READY, ready, 1)
        state, result = call(project, state, LINK, 2, 1, 160)
        results.append((state, ready, result))
    project.hook(LINK, link_class())
    return [dict(map_ready_before=ready, result=result, after=observe(project, state),
                 recovery_reentry=list(state.globals.get("recovery", ())))
            for state, ready, result in results]


def replay(elf):
    project = load_project(elf)
    import angr

    link_class = install(project, angr)
    expected = reference()
    startup = []
    for case in INIT_CASES:
        state = seed(project, angr)
        state.globals["case"] = case
        state, result = call(project, state, INIT, 1)
        if case == "success":
            booted = state
        if case != "already-powered":
            check_maps(state, {} if case == "partial-map-fails" else permissions(case))
        row = dict(case=case, after=observe(project, state), llc=list(state.globals.get("llc", ())),
                   transport=list(state.globals.get("transport", ())),
                   power_requests=list(state.globals.get("power", ())),
                   retry_messages=list(state.globals.get("messages", ())),
                   early_return_2=result == 2)
        assert row == expected["startup_cases"][len(startup)], (row, expected["startup_cases"][len(startup)])
        startup.append(row)
    cache = []
    for case, entry in zip(CACHE_CASES, (SINGLE, VD_SYNC, VD_SYNC, PRIMARY), strict=True):
        state = booted.copy()
        state.globals["case"], state.globals["transport"] = case, ()
        state, _ = call(project, state, entry)
        row = dict(case=case, after=observe(project, state), transport=list(state.globals["transport"]))
        assert row == expected["cache_cases"][len(cache)], (row, expected["cache_cases"][len(cache)])
        cache.append(row)
    resets = []
    for case, entry in zip(RESET_CASES, (RESET, MOUNT_SWITCH, DETECT, DETECT), strict=True):
        state = booted.copy()
        state.globals["case"], state.globals["power"] = case, ()
        state.globals["detect_pin"] = int(entry == DETECT)
        put(state, LATCH, int(case == "detect-with-latch"), 1)
        state, _ = call(project, state, entry)
        row = dict(case=case, after=observe(project, state), latch=get(state, LATCH, 1),
                   power_requests=list(state.globals["power"]))
        assert row == expected["reset_cases"][len(resets)], (row, expected["reset_cases"][len(resets)])
        if case != "detect-without-latch":
            check_maps(state, {})
        resets.append(row)
    timeouts = run_timeouts(project, angr, link_class)
    report = dict(expected, startup_cases=startup, cache_cases=cache, reset_cases=resets,
                  timeout_cases=timeouts, engine=f"angr {angr.__version__} / VEX")
    validate_report(report)
    return report


def validate_report(report):
    """Check the deterministic fixture metadata without firmware or angr."""
    if not __debug__:
        raise RuntimeError("Validation requires assertions")
    engine = report["engine"]
    assert engine.startswith("angr ") and engine.endswith(" / VEX")
    assert report == dict(reference(), engine=engine), (report["timeout_cases"], reference()["timeout_cases"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error("replay requires assertions")
    if args.output.exists():
        parser.error("output must not exist")
    report = replay(args.elf)
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print("PASS 7 startup, 4 cache, 4 reset/detect, 2 native timeout cases")


if __name__ == "__main__":
    main()
