"""Replay Q7 FC1 top controls and the two independent payload fields with VEX."""
import argparse
import json
import struct
from pathlib import Path

from check_fiplib_coefficients import HDR
from check_isp_registers import ELF_SHA256, load_project, RETURN_PC, STACK_TOP


PASS, INPUT, TOPOLOGY, PAYLOAD = 0x10001000, 0x10002000, 0x10004000, 0x10005000
LOCAL, FC, GENERAL = PASS + 0x88C, PASS + 0x118, PASS + 0x14
HELPER = 0x801775E0
CONTROL_METHODS = {
    # operation modes (when needed), top block controls, miscellaneous inputs
    'base': (None, 0x80177468, 0x80177588),
    '1x0': (0x8017BBA8, 0x8017BC80, 0x80177588),
    '1x1': (0x80171670, 0x80171758, 0x80171A58),
    '2x0': (0x8017BD18, 0x8017BDA4, 0x8017BFDC),
    '0x1': (0x80178770, 0x801788B0, 0x80178EA0),
    '5x1': (0x8017B9FC, 0x80177468, 0x80177588),
}
EXPORTS = (0x80179CAC, 0x80179F90, 0x8017A974, 0x8017AB94, 0x8017AD04)
NR_FIELDS = (0x16F4, 0x16F8, 0x1712, 0x171A, 0x171C)
INITIAL_BYPASS, INITIAL_FLAGS = 0xA5, 0xD7
SCOPE = ('Concrete MIPS replay of FC1 block-control methods and payload export. '
         'Synthetic input/topology, no stubs, MMIO, scheduling or camera execution.')


def expected(case):
    name, t, s, d, q = (case[k] for k in ('pass_class', 'topology_word', 'input_1', 'input_1072', 'input_9'))
    fields = case['helper_fields']
    helper = (any(fields['nr_halfwords']) or fields['lc_word'] != 1 or
              (fields['input_2'] != 1 and (fields['input_1070'] != 1 or fields['input_c74'] != 1)))
    if name == '0x1' and q > 6:
        bypass, flags = INITIAL_BYPASS, INITIAL_FLAGS
    elif name == '1x0' or (name == '0x1' and q == 6):
        bypass, flags = 1, 0
    elif name in ('base', '5x1') or (name == '0x1' and q in (2, 3, 5)):
        bypass, flags = int(t == 0), 0
    else:
        flags = int(t == 0)
        bypass = int(d == 1 if s == 0 else (t == 0 or (name != '2x0' and not helper)))
    return dict(helper=int(helper), local_bypass=bypass, local_flag_byte=flags,
                payload_bypass_word=bypass, payload_flag_word=flags & 1)


def reference_cases():
    def case(name, pass_class, t=0, s=0, d=0, q=0, phase=None, **helper_fields):
        inputs = dict(nr_halfwords=[0]*5, lc_word=1, input_2=0, input_1070=1, input_c74=1)
        inputs.update(helper_fields)
        result = dict(case=name, pass_class=pass_class, topology_word=t, input_1=s,
                      input_1072=d, input_9=q, helper_fields=inputs)
        if phase is not None:
            result['input_1738'] = phase
        return dict(**result, expected=expected(result))

    for name in ('base', '1x0', '1x1', '2x0', '0x1'):
        for t in (0, 1, 2):
            yield case(f'{name}-hdr-like-t{t}', name, t=t)
    yield case('base-full-word', 'base', t=0x100)
    for name in ('1x1', '2x0', '0x1'):
        yield case(f'{name}-requested-bypass', name, t=2, d=1)
        yield case(f'{name}-requested-byte-2', name, t=2, d=2)
        yield case(f'{name}-selector-nonzero-t0', name, s=1)
        yield case(f'{name}-selector-nonzero-helper-off', name, t=1, s=2)
        yield case(f'{name}-selector-nonzero-helper-on', name, t=1, s=1, lc_word=0)
    for q in range(1, 8):
        yield case(f'0x1-q{q}', '0x1', t=2, q=q)
    for q in (1, 2, 3, 4, 5):
        yield case(f'0x1-q{q}-t0', '0x1', q=q, d=1)
    yield case('0x1-qff-no-write', '0x1', t=2, q=255)
    for i, offset in enumerate(NR_FIELDS):
        nr_halfwords = [0]*5
        nr_halfwords[i] = 0x8000
        yield case(f'helper-u16-{offset:x}', '1x1', t=1, s=1, nr_halfwords=nr_halfwords)
    yield case('helper-input-2-override', '1x1', t=1, s=1, input_2=1, input_1070=0, input_c74=0)
    yield case('helper-input-2-exact', '1x1', t=1, s=1, input_2=2, input_1070=0, input_c74=0)
    yield case('helper-lc-full-word', '1x1', t=1, s=1, lc_word=0x10001)
    yield case('helper-input-1070-exact', '0x1', t=1, s=1, input_1070=2)
    yield case('helper-input-c74-exact', '0x1', t=1, s=1, input_c74=2)
    for index, (name, t) in enumerate((('1x0', 1), ('1x1', 1), ('5x1', 0), ('0x1', 1))):
        yield case(f'fresh-hdr-pass-{index}', name, t=t, phase=0)


def reference():
    functions = sorted({HELPER, *EXPORTS, *(f for group in CONTROL_METHODS.values() for f in group if f)})
    return dict(analysis_elf_sha256=ELF_SHA256, scope=SCOPE, functions=[hex(f) for f in functions],
                cases=list(reference_cases()))


def validate_report(report):
    engine = report.get('engine', '')
    if not isinstance(engine, str) or not engine.startswith('angr ') or not engine.endswith(' / VEX'):
        raise ValueError('invalid FC1 replay engine')
    if report != dict(**reference(), engine=engine):
        raise ValueError('FC1 control replay differs from its reference cases')


def replay_case(project, angr, case):
    state = project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp = STACK_TOP
    regions = [(PASS, 0xA40), (INPUT, 0x1790), (TOPOLOGY, 0x40), (PAYLOAD, 0x5E0)]
    for addr, size in regions:
        state.memory.store(addr, bytes(size))
    regions.append((STACK_TOP - 0x100, 0x100))

    def put(address, value, kind='B'):
        state.memory.store(address, struct.pack('<' + kind, value))

    put(TOPOLOGY+4, TOPOLOGY+0x10, 'I')
    put(TOPOLOGY+8, TOPOLOGY+0x18, 'I')
    put(TOPOLOGY+0xC, TOPOLOGY+0x24, 'I')
    put(TOPOLOGY+0x10, case['topology_word'], 'I')
    fields = case['helper_fields']
    for offset, value in [(1, case['input_1']), (2, fields['input_2']), (7, 1), (9, case['input_9']),
                          (0xC74, fields['input_c74']), (0x1070, fields['input_1070']),
                          (0x1072, case['input_1072']), (0x108C, 1), (0x1738, case.get('input_1738', 1))]:
        put(INPUT+offset, value)
    for offset, value in zip(NR_FIELDS, fields['nr_halfwords'], strict=True):
        put(INPUT+offset, value, 'H')
    put(INPUT+0x1420, fields['lc_word'], 'I')
    state.memory.store(INPUT+0x1074, struct.pack('<11h', *HDR))
    put(LOCAL+0x24, INITIAL_BYPASS)
    put(LOCAL+0x28, INITIAL_FLAGS)

    def guard(s, addr, width):
        if s.solver.symbolic(addr) or s.solver.symbolic(width):
            raise RuntimeError(f'{case["case"]}: symbolic memory access')
        addr, width = s.solver.eval(addr), s.solver.eval(width)
        if not any(base <= addr < addr+width <= base+size for base, size in regions):
            raise RuntimeError(f'{case["case"]}: out-of-range memory access at {addr:#x}')

    def on_read(s):
        a = s.inspect.attrs
        guard(s, a.mem_read_address, a.mem_read_length)

    def on_write(s):
        a = s.inspect.attrs
        guard(s, a.mem_write_address, a.mem_write_length)

    def call(address, a0, a1, a2=0):
        nonlocal state
        state.regs.pc, state.regs.ra = address, RETURN_PC
        state.regs.a0, state.regs.a1, state.regs.a2 = a0, a1, a2
        sim = project.factory.simgr(state, save_unconstrained=True)
        sim.explore(find=RETURN_PC, n=128)
        if len(sim.found) != 1 or sim.active or sim.errored or sim.deadended or sim.unconstrained:
            raise RuntimeError(f'{case["case"]}: incomplete replay at {address:#x}: {sim.errored}')
        state = sim.found[0]
        if state.solver.eval_one(state.regs.sp) != STACK_TOP:
            raise RuntimeError(f'{case["case"]}: unrestored stack at {address:#x}')

    def read(address, size):
        return state.solver.eval_one(state.memory.load(address, size, endness='Iend_LE'))

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=on_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)
    call(HELPER, PASS, INPUT)
    helper = state.solver.eval_one(state.regs.v0)
    operation_modes, top, misc = CONTROL_METHODS[case['pass_class']]
    if operation_modes:
        call(operation_modes, PASS, INPUT, TOPOLOGY)
        if read(LOCAL+3, 1) != case['input_1']:
            raise RuntimeError(f'{case["case"]}: operation mode failed to copy input selector')
    call(top, PASS, INPUT, TOPOLOGY)
    bypass, flags = read(LOCAL+0x24, 1), read(LOCAL+0x28, 1)
    call(misc, PASS, INPUT)
    call(EXPORTS[0], GENERAL, LOCAL)
    call(EXPORTS[1], GENERAL, PAYLOAD)
    call(EXPORTS[2], FC, 1)
    call(EXPORTS[3], FC, LOCAL)
    call(EXPORTS[4], FC, PAYLOAD+0x100)
    actual = dict(helper=helper, local_bypass=bypass, local_flag_byte=flags,
                  payload_bypass_word=read(PAYLOAD+0x44, 4), payload_flag_word=read(PAYLOAD+0x12C, 4))
    if actual != case['expected']:
        raise RuntimeError(f'{case["case"]}: expected {case["expected"]}, got {actual}')


def replay(elf):
    import angr
    project = load_project(elf)
    if project.arch.name != 'MIPS32' or project.arch.memory_endness != 'Iend_LE':
        raise ValueError('expected little-endian MIPS32 ELF')
    report = reference()
    for case in report['cases']:
        replay_case(project, angr, case)
    return dict(**report, engine=f'angr {angr.__version__} / VEX')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must not exist')
    report = replay(args.elf)
    validate_report(report)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(f'{len(report["cases"])} FC1 top-control replay cases passed')


if __name__ == '__main__':
    main()
