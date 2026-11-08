"""Replay Q7 topology input classification and alternate FC1 control-word sources."""
import argparse
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256, load_project, RETURN_PC, STACK_TOP


OBJ, DESCRIPTOR, PAYLOAD = 0x10001000, 0x10002000, 0x10003000
TOPOLOGY_CTOR, SET_INPUT, SET_OUTPUT = 0x8017C148, 0x8017C304, 0x8017C2F4
IMAGE_TYPE_NAME, MAP_INPUT = 0x8009FE58, 0x8034C904
FC1_CTOR, SET_FILTER, WRITE_REGISTERS = 0x8031F56C, 0x80321BE8, 0x8031F750
FC1_VTABLE = 0x804FF9F0
CONTROL_MMIO = 0xB60000FC
SOURCE_COEFFICIENTS = (31, -49, 7, -11, 100, 203, -19, 59, -14)
SOURCE_TAIL = (19, -43)
IMAGE_TYPES = (
    (1, 'BAYER_8', 0), (2, 'BAYER_10', 15), (3, 'BAYER_12', 9),
    (4, 'BAYER_16', 1), (5, 'RGB_24', 4), (6, 'RGB_48', 13),
    (7, 'YUV_420', 20), (8, 'YUV_422', 2), (11, 'YUV_444', 3),
    (12, 'YUV_444_16', 13), (13, 'YUV_422_VD', 19),
    (14, 'YUV_444_12_10_10', 16), (15, 'YUV_444_12_48', 17),
    (16, 'RGB_10_12_10', 22), (17, 'LUMA-Y', 0),
    (19, 'LIMAGE_16', 14), (20, 'LIMAGE_32', 18),
)
SCOPE = ('Original MIPS image-type name and input-format mapping, IPU topology constructor and format '
         'setters, and FC1 constructor, descriptor dispatcher and direct writer. Synthetic objects '
         'and RAM MMIO with no stubs. No scheduling, camera or ISP datapath execution.')


def input_type(input_format):
    if input_format in (0, 1, 9):
        return 2
    if input_format in (4, 13):
        return 1
    return 0


def topology_case(input_format, **fields):
    changed_input = 13 if input_type(input_format) == 0 else 2
    return dict(**fields, input_format=input_format, topology_input_type=input_type(input_format),
                changed_input_format=changed_input, changed_output_formats=[2, 4, 13])


def writer_case(descriptor_id, version, control):
    if descriptor_id == 0xF:
        scale = {0: 8, 6: 4}.get(version, 1)
        coeffs = [v * scale for v in SOURCE_COEFFICIENTS]
        tail = [v * 8 + 0x800 for v in SOURCE_TAIL] if version in (0, 6) else SOURCE_TAIL
        emitted = 0 if version in (0, 6) else control
    else:
        coeffs = ([v >> 2 for v in SOURCE_COEFFICIENTS] if version == 0xF else SOURCE_COEFFICIENTS)
        tail, emitted = SOURCE_TAIL, control
    mmio = [[0xB60000C0 + 4 * i, 4, v & 0xFFFFFFFF] for i, v in enumerate((*coeffs, *tail))]
    mmio.append([CONTROL_MMIO, 4, emitted])
    return dict(descriptor_id=descriptor_id, version=version, source_control_word=control,
                emitted_control_word=emitted, ordered_mmio_writes=mmio)


def reference():
    formats = [topology_case(f) for f in (*range(26), 26, 0xFFFFFFFF)]
    mappings = [topology_case(f, descriptor_type=i, descriptor_type_name=name)
                for i, name, f in IMAGE_TYPES]
    versions = [(0xF, v) for v in (0, 6, 0xC, 0xD, 0xF)] + [(0xAB, v) for v in (0xC, 0xF)]
    cases = [writer_case(i, v, control) for i, v in versions
             for control in (0xA5920040, 0xA5920041)]
    return dict(analysis_elf_sha256=ELF_SHA256, scope=SCOPE, topology_format_cases=formats,
                descriptor_mapping_cases=mappings, source_coefficients=list(SOURCE_COEFFICIENTS),
                source_tail=list(SOURCE_TAIL), descriptor_writer_cases=cases)


def validate_report(report):
    engine = report.get('engine', '')
    if not isinstance(engine, str) or not engine.startswith('angr ') or not engine.endswith(' / VEX'):
        raise ValueError('invalid FC1 semantics replay engine')
    if report != dict(**reference(), engine=engine):
        raise ValueError('FC1 semantics replay differs from its reference cases')


def replay_case(project, angr, case):
    state = project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp = STACK_TOP
    ram = ((OBJ, 0x100), (DESCRIPTOR, 0x40), (PAYLOAD, 0x140), (STACK_TOP - 0x100, 0x120))
    readonly = ((0x800BDE40, 28 * 4), (0x8035ABD8, 21 * 4), (0x803588F4, 16 * 4),
                (FC1_VTABLE + 0x48, 8))
    mmio = {(a, n) for a, n, _ in case.get('ordered_mmio_writes', [])}
    events = []
    for address, size in ram:
        state.memory.store(address, bytes(size))

    def put(address, *values, kind='I'):
        state.memory.store(address, struct.pack('<' + kind * len(values), *values), inspect=False)

    def concrete(current, value):
        if current.solver.symbolic(value):
            raise RuntimeError('symbolic value during concrete replay')
        return current.solver.eval(value)

    def get(address):
        return concrete(state, state.memory.load(address, 4, endness='Iend_LE', inspect=False))

    def within(addr, width, regions):
        return any(base <= addr < addr + width <= base + size for base, size in regions)

    def on_read(s):
        attrs = s.inspect.attrs
        addr, width = (concrete(s, v) for v in (attrs.mem_read_address, attrs.mem_read_length))
        if not within(addr, width, (*ram, *readonly)):
            raise RuntimeError(f'out-of-range read at {addr:#x}')

    def on_write(s):
        attrs = s.inspect.attrs
        addr, width = (concrete(s, v) for v in (attrs.mem_write_address, attrs.mem_write_length))
        if (addr, width) in mmio:
            events.append([addr, width, concrete(s, attrs.mem_write_expr)])
        elif not within(addr, width, ram):
            raise RuntimeError(f'out-of-range write at {addr:#x}')

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=on_read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=on_write)

    def call(address, *args):
        nonlocal state
        state.regs.pc, state.regs.ra = address, RETURN_PC
        for index, value in enumerate(args[:4]):
            setattr(state.regs, f'a{index}', value)
        for index, value in enumerate(args[4:], start=4):
            put(STACK_TOP + index * 4, value)
        sim = project.factory.simgr(state, save_unconstrained=True)
        sim.explore(find=RETURN_PC, n=128)
        if len(sim.found) != 1 or sim.active or sim.errored or sim.deadended or sim.unconstrained:
            raise RuntimeError(f'failed replay at {address:#x} with {case}: {sim.errored}')
        state = sim.found[0]
        if concrete(state, state.regs.sp) != STACK_TOP:
            raise RuntimeError(f'stack imbalance after {address:#x}')
        return concrete(state, state.regs.v0)

    if 'input_format' in case:
        input_format = case['input_format']
        if 'descriptor_type' in case:
            image_type = case['descriptor_type']
            address = call(IMAGE_TYPE_NAME, image_type)
            name = project.loader.memory.load(address, len(case['descriptor_type_name']) + 1)
            if name != case['descriptor_type_name'].encode('ascii') + b'\0' or call(MAP_INPUT, image_type) != input_format:
                raise RuntimeError(f'image descriptor mapping differs for {case}')
        call(TOPOLOGY_CTOR, OBJ, 0, 0, 0, input_format)
        expected_type = case['topology_input_type']
        if (get(OBJ + 0x88), get(OBJ + 0x18), get(OBJ + 0x50)) != (OBJ + 0x18, expected_type, input_format):
            raise RuntimeError(f'topology constructor differs for {case}')
        changed_input, outputs = case['changed_input_format'], case['changed_output_formats']
        call(SET_INPUT, OBJ, changed_input)
        call(SET_OUTPUT, OBJ, *outputs)
        if (get(OBJ + 0x88), get(OBJ + 0x18), get(OBJ + 0x50)) != (OBJ + 0x18, expected_type, changed_input):
            raise RuntimeError(f'topology setters changed type for {case}')
        if [get(OBJ + off) for off in (0x44, 0x48, 0x4C)] != outputs:
            raise RuntimeError(f'topology output fields differ for {case}')
        return

    descriptor_id, version, control = (case[k] for k in ('descriptor_id', 'version', 'source_control_word'))
    call(FC1_CTOR, OBJ, 0)
    put(OBJ + 0x48, 0xFFFFFFFF)
    put(DESCRIPTOR + 4, descriptor_id, version)
    if descriptor_id == 0xF:
        put(DESCRIPTOR + 0x14, *SOURCE_COEFFICIENTS, *SOURCE_TAIL, kind='h')
        put(DESCRIPTOR + 0x2C, control)
    else:
        put(DESCRIPTOR + 0x1C, PAYLOAD)
        put(PAYLOAD + 0x100, *SOURCE_COEFFICIENTS, *SOURCE_TAIL, kind='i')
        put(PAYLOAD + 0x12C, control)
    if call(SET_FILTER, OBJ, DESCRIPTOR) != 0 or get(OBJ + 0x48) != case['emitted_control_word']:
        raise RuntimeError(f'FC1 setter differs for {case}')
    call(WRITE_REGISTERS, OBJ)
    if events != case['ordered_mmio_writes']:
        raise RuntimeError(f'FC1 stores differ for {case}: {events}')


def replay(elf):
    import angr

    project = load_project(elf)
    if project.arch.name != 'MIPS32' or project.arch.memory_endness != 'Iend_LE':
        raise ValueError('expected little-endian MIPS32 ELF')
    report = reference()
    for key in ('topology_format_cases', 'descriptor_mapping_cases', 'descriptor_writer_cases'):
        for case in report[key]:
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
    print('28 topology, 17 image descriptor and 14 FC1 writer replay cases passed')


if __name__ == '__main__':
    main()
