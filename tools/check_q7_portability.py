"""Replay Q7 AF peak fitting and the indexed LCD icon path on synthetic RAM."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP


APPROXIMATION = 0x8037D704
ICON_SIZE, ICON_DATA_WIDTH, ICON_DRAW = 0x8043F288, 0x8043F3A4, 0x8043F42C
DIRECT_OSD_GET_BUFFER = 0x80262FD4
SCREEN_SIZE = 0x80439428
POSITIONS, CONTRAST = 0x10001000, 0x10002000
SIZE, DECODED, FRAME = 0x10003000, 0x10004000, 0x10005000
ICON = dict(id=30, width=32, height=16, data_va=0x808AE948, data_size=144)
STYLES = (0, 1)
FOREGROUND, FILL, X, Y = 0xCE, 0xA5, 3, 2
STRIDE = ICON['width'] + 8
FRAME_SIZE = STRIDE * (ICON['height'] + 4)
SIZE_CASES = [(1, 64, 48, 85), (30, 24, 16, 32), (248, 256, 48, 341),
              (1001, 96, 80, 128), (1546, 48, 48, 64)]


def fit_cases():
    for xs, peak in [([-2, -1, 0, 1, 2], 1), ([-8, -6, -4, -2, 0], -4),
                     ([0, 2, 4, 6, 8], 5), ([0, 2, 4], 1),
                     (list(range(10)), 4), (list(range(11)), 4)]:
        yield dict(positions=xs, contrast=[100 - (x - peak)**2 for x in xs],
                   expected=peak if len(xs) < 11 else 0)


def u32(value):
    return struct.pack('<I', value & 0xFFFFFFFF)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def new_state(project, angr):
    state = project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp = STACK_TOP
    state.memory.store(STACK_TOP - 0x400, bytes(0x440))
    return state


def guard(state, angr, ram, readonly=()):
    stack = (STACK_TOP - 0x400, STACK_TOP + 0x40)

    def check(st, address, length, allowed):
        if st.solver.symbolic(address) or st.solver.symbolic(length):
            raise RuntimeError('symbolic memory access in Q7 replay')
        address, length = st.solver.eval(address), st.solver.eval(length)
        if not any(lo <= address < address + length <= hi for lo, hi in allowed):
            raise RuntimeError(f'out-of-range Q7 access at {address:#x}, size {length}')

    def read(st):
        a = st.inspect.attrs
        check(st, a.mem_read_address, a.mem_read_length, (stack, *ram, *readonly))

    def write(st):
        a = st.inspect.attrs
        check(st, a.mem_write_address, a.mem_write_length, (stack, *ram))

    state.inspect.b('mem_read', when=angr.BP_BEFORE, action=read)
    state.inspect.b('mem_write', when=angr.BP_BEFORE, action=write)


def execute(project, state, pc, *args, steps=6000):
    state.regs.ra, state.regs.pc = RETURN_PC, pc
    for i, value in enumerate(args[:4]):
        setattr(state.regs, f'a{i}', value & 0xFFFFFFFF)
    for i, value in enumerate(args[4:], start=4):
        state.memory.store(STACK_TOP + 4*i, u32(value), inspect=False)
    sim = project.factory.simgr(state, save_unconstrained=True)
    sim.explore(find=RETURN_PC, n=steps)
    if len(sim.found) != 1 or sim.active or sim.errored or sim.deadended or sim.unconstrained:
        raise RuntimeError(f'Q7 replay failed at {pc:#x}: {sim.errored}')
    state = sim.found[0]
    assert state.solver.eval(state.regs.sp) == STACK_TOP
    return state


def value(state, address, length):
    item = state.memory.load(address, length, inspect=False)
    assert not state.solver.symbolic(item)
    return state.solver.eval(item, cast_to=bytes)


def fit(project, angr, case):
    state = new_state(project, angr)
    xs, ys = case['positions'], case['contrast']
    count = len(xs)
    ram = ((0x80C24BD4, 0x80C24F18),)
    state.memory.store(ram[0][0], bytes(ram[0][1] - ram[0][0]))
    readonly = ((0x803B7C00, 0x803B7C08),)
    if count <= 10:
        state.memory.store(POSITIONS, struct.pack(f'<{count}i', *xs))
        state.memory.store(CONTRAST, struct.pack(f'<{count}f', *ys))
        readonly += ((POSITIONS, POSITIONS + 4*count), (CONTRAST, CONTRAST + 4*count))
    guard(state, angr, ram, readonly)
    state = execute(project, state, APPROXIMATION, count, POSITIONS, CONTRAST)
    assert state.solver.eval(state.regs.v0) == case['expected'] & 0xFFFFFFFF
    assert value(state, 0x80C24BD4, 4) == u32(count)


def geometry(project, angr):
    results = []
    readonly = ((0x808A786C, 0x808A7E3C), (0x80878858, 0x80879524))
    for ident, width, height, data_width in SIZE_CASES:
        state = new_state(project, angr)
        state.memory.store(SIZE, bytes(4))
        guard(state, angr, ((SIZE, SIZE + 4),), readonly)
        state = execute(project, state, ICON_SIZE, SIZE, ident)
        assert value(state, SIZE, 4) == struct.pack('<HH', width, height)
        state = execute(project, state, ICON_DATA_WIDTH, ident)
        assert state.solver.eval(state.regs.v0) == data_width
        results.append(dict(icon_id=ident, layout_width=width, height=height, data_width=data_width))

    state = new_state(project, angr)
    state.memory.store(SIZE, bytes(4))
    state.memory.store(0x80C6AE44, u32(2))
    guard(state, angr, ((SIZE, SIZE + 4),),
          ((0x80C6AE44, 0x80C6AE48), (0x804E86D0, 0x804E86D4), (0x804E86AC, 0x804E86D0)))
    state = execute(project, state, SCREEN_SIZE, SIZE)
    assert value(state, SIZE, 4) == struct.pack('<HH', 960, 480)
    return dict(icon_sizes=results, lcd_screen_mode=2, reported_logical_size=[960, 480])


def draw(project, angr):
    class BufferInRam(angr.SimProcedure):
        def run(self, buffer_id, out, width, height):
            assert self.state.solver.eval(buffer_id) == 17
            self.state.memory.store(out, u32(FRAME), size=4)
            self.state.memory.store(width, struct.pack('<H', STRIDE), size=2)
            self.state.memory.store(height, struct.pack('<H', FRAME_SIZE // STRIDE), size=2)
            return 1

    project.hook(DIRECT_OSD_GET_BUFFER, BufferInRam())
    size = ICON['width'] * ICON['height']
    source = project.loader.memory.load(ICON['data_va'], ICON['data_size'])
    decoded = b''.join(bytes([value])*count for value, count in zip(source[::2], source[1::2], strict=True))
    assert len(decoded) == size and 0 in decoded and 1 in decoded and max(decoded) > 1
    index = ICON['id'] - 1
    offset, flag = 0x804A1620 + index*4, 0x804A1A00 + index
    results = []
    for style in STYLES:
        state = new_state(project, angr)
        state.memory.store(0x804A161C, u32(DECODED))
        state.memory.store(offset, u32(0))
        state.memory.store(flag, b'\0')
        state.memory.store(0x80C6AE44, u32(2))
        state.memory.store(0x80C6AE84, struct.pack('<H', 17))
        state.memory.store(0x80C6AE94, bytes(2))
        state.memory.store(DECODED, bytes(size))
        state.memory.store(FRAME, bytes([FILL])*FRAME_SIZE)
        ram = ((flag, flag+1), (DECODED, DECODED+size), (FRAME, FRAME+FRAME_SIZE))
        readonly = ((0x804A161C, 0x804A1620), (offset, offset+4), (0x80C6AE44, 0x80C6AE48),
                    (0x80C6AE84, 0x80C6AE86), (0x80C6AE94, 0x80C6AE96),
                    (0x804E86AC, 0x804E86D0), (0x808A786C, 0x808A821C),
                    (ICON['data_va'], ICON['data_va']+ICON['data_size']))
        guard(state, angr, ram, readonly)
        state = execute(project, state, ICON_DRAW, ICON['id'], X, Y, style, FOREGROUND)
        expected = bytearray([FILL])*FRAME_SIZE
        for i, pixel in enumerate(decoded):
            if pixel:
                row, col = divmod(i, ICON['width'])
                expected[(Y+row)*STRIDE + X+col] = FOREGROUND if style == 1 and pixel != 1 else pixel
        assert value(state, flag, 1) == b'\x01'
        assert value(state, DECODED, size) == decoded
        assert value(state, FRAME, FRAME_SIZE) == expected
        results.append(dict(style=style, decoded_sha256=digest(decoded), draw_buffer_sha256=digest(expected),
                            nontransparent_pixels=sum(p != 0 for p in decoded)))
    return dict(icon=ICON, start_xy=[X, Y], stride_bytes=STRIDE, frame_size_bytes=FRAME_SIZE,
                initial_byte=FILL, recolor_index=FOREGROUND, cases=results)


def replay(elf):
    if not __debug__:
        raise RuntimeError('replay requires assertions')
    if digest(elf.read_bytes()) != ELF_SHA256:
        raise ValueError('expected SHA-pinned Q7 ELF')
    import angr

    project = angr.Project(str(elf), auto_load_libs=False)
    if project.arch.name != 'MIPS32' or project.arch.memory_endness != 'Iend_LE':
        raise ValueError('expected little-endian MIPS32 ELF')
    cases = list(fit_cases())
    for case in cases:
        fit(project, angr, case)
    return dict(analysis_elf_sha256=ELF_SHA256, engine=f'angr {angr.__version__} / VEX',
                af_fit_cases=cases, geometry=geometry(project, angr), icon_draw=draw(project, angr),
                icon_draw_stubs=['0x80262fd4 supplies a synthetic draw buffer and stride'])



def validate_report(report):
    engine = report.get('engine', '')
    if not isinstance(engine, str) or not engine.startswith('angr ') or not engine.endswith(' / VEX'):
        raise ValueError('invalid Q7 portability replay engine')
    sizes = [dict(icon_id=i, layout_width=w, height=h, data_width=p) for i, w, h, p in SIZE_CASES]
    geometry_result = dict(icon_sizes=sizes, lcd_screen_mode=2, reported_logical_size=[960, 480])
    draw_hashes = (
        'b67fe035b9325010e66b3280b5fbb915f07e8e9266b4e624cbd3b3f7818f70bb',
        '43462d645e1fd4ba8a06372606ff97252b65e14f45bf4f71ce9d27440cbf3b24',
    )
    decoded_hash = '691965421aa9b352b162c0501091344ef3cccf1ce54184ccfc8999823f13b2bf'
    draws = [dict(style=style, decoded_sha256=decoded_hash, draw_buffer_sha256=frame_hash,
                  nontransparent_pixels=328)
             for style, frame_hash in zip(STYLES, draw_hashes, strict=True)]
    draw_result = dict(icon=ICON, start_xy=[X, Y], stride_bytes=STRIDE, frame_size_bytes=FRAME_SIZE,
                       initial_byte=FILL, recolor_index=FOREGROUND, cases=draws)
    expected = dict(analysis_elf_sha256=ELF_SHA256, engine=engine, af_fit_cases=list(fit_cases()),
                    geometry=geometry_result, icon_draw=draw_result,
                    icon_draw_stubs=['0x80262fd4 supplies a synthetic draw buffer and stride'])
    if report != expected:
        raise ValueError('Q7 portability replay differs from the reference cases')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output must not exist')
    report = replay(args.elf)
    validate_report(report)
    with args.output.open('x', encoding='utf-8', newline='\n') as file:
        json.dump(report, file, indent=2)
        file.write('\n')
    print('6 AF fitting cases, 6 geometry cases and 2 indexed icon draw cases passed')


if __name__ == '__main__':
    main()
