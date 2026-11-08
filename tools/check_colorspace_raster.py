"""Replay original solid-line and 8-bit GDI raster paths on bounded synthetic RAM."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path

from check_colorspace_render import frame_commands, set_screen
from check_colorspace_ui import concrete, get, put, record
from check_isp_registers import ELF_SHA256, load_project
from check_q7_portability import execute, guard, new_state, value

FRAME, CTX, TABLE = 0x22000000, 0x21000000, 0x21010000
WIDTH, HEIGHT, FILL = 736, 176, 0xA5
CREATE, BITMAP, SELECT = 0x802181FC, 0x80220D60, 0x80218368
TEMPLATE, DRAW = 0x802353B8, 0x8043EB54
BRANCHES = {0x8043EC98: 'word', 0x8043ED40: 'halfword', 0x8043EBDC: 'gdi'}
MODELED = {
    '0x8000bf28': 'Return zeroed synthetic allocations for one display context and one bitmap.',
    '0x80262fd4': 'Return synthetic buffer ID17 metadata: 736-byte stride and176 rows.',
    '0x800b3d40': 'Record cache address/length and return0 without CPU cache operations.',
}
CASES = (
    ('srgb-highlight', frame_commands(64)),
    ('adobergb-highlight', frame_commands(112)),
    ('word-aligned', [[0, 2, 32, 2, 77, 0]]),
    ('halfword-aligned', [[0, 2, 16, 2, 78, 0]]),
    ('odd-x-gdi', [[1, 2, 32, 2, 79, 0]]),
    ('gdi-clipped-edge', [[733, 174, 7, 4, 77, 0]]),
    ('zero-height', [[0, 2, 32, 0, 77, 0]]),
)
FIXTURE = 'Original 8-bit context template; synthetic default and ID17 binding; identity coordinate scaling.'


def digest(data):
    return sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate_report(report):
    if not __debug__:
        raise RuntimeError('Validation requires assertions')
    assert report['analysis_elf_sha256'] == ELF_SHA256
    assert report['engine'].startswith('angr ') and report['engine'].endswith(' / VEX')
    assert report['modeled_boundaries'] == MODELED
    assert report['buffer'] == dict(stride=WIDTH, height=HEIGHT, fill=FILL)
    assert report['fixture'] == FIXTURE and report['context_fill_function'] == '0x80225820'
    assert digest(report['cases']) == '0205f499f909d4bca39915c47a96b7e38818060f54a08fdb877ca087ec5924f9'


def prepare(project, angr):
    class Allocate(angr.SimProcedure):
        def run(self, pool, size):
            size = concrete(self.state, size)
            assert size in (0x8B0, 12)
            address = CTX if size == 0x8B0 else CTX+0x1000
            self.state.memory.store(address, bytes(size), size=size)
            return address

    class Buffer(angr.SimProcedure):
        def run(self, index, out, width, height):
            assert concrete(self.state, index) == 17
            for pointer, number, size in ((out, FRAME, 4), (width, WIDTH, 2), (height, HEIGHT, 2)):
                self.state.memory.store(concrete(self.state, pointer), number.to_bytes(size, 'little'), size=size)
            return 1

    class Cache(angr.SimProcedure):
        def run(self, address, size):
            event = [concrete(self.state, address), concrete(self.state, size)]
            assert event == [FRAME, WIDTH*HEIGHT]
            record(self.state, 'cache', event)
            return 0

    for pc, hook in ((0x8000BF28, Allocate()), (0x80262FD4, Buffer()), (0x800B3D40, Cache())):
        project.hook(pc, hook)
    state = new_state(project, angr)
    set_screen(state)
    put(state, 0x800EB4D8, CTX)
    put(state, 0x800EBD70, 32)
    put(state, 0x8029F340, TABLE)
    state.memory.store(TABLE, bytes(0x100))
    put(state, TABLE+4+17*4, CTX)
    state.memory.store(FRAME-8, b'G'*8 + bytes([FILL])*(WIDTH*HEIGHT) + b'G'*8)
    ram = ((CTX, CTX+0x8B0), (CTX+0x1000, CTX+0x100C), (FRAME, FRAME+WIDTH*HEIGHT))
    # Original data reads are permitted; all writes remain confined to context, bitmap, frame and stack.
    readonly = tuple((segment.min_addr, segment.max_addr+1) for segment in project.loader.main_object.segments)
    guard(state, angr, ram, (*readonly, (TABLE, TABLE+0x100), (0x80C6AE30, 0x80C6AEB0),
                            (0x800EB4D8, 0x800EB4DC), (0x800EBD70, 0x800EBD74),
                            (0x8029F340, 0x8029F344)))
    state = execute(project, state, CREATE, 0, TEMPLATE)
    assert concrete(state, state.regs.v0) == CTX
    state = execute(project, state, BITMAP, 0, WIDTH, HEIGHT, 8, FRAME)
    assert concrete(state, state.regs.v0) == CTX+0x1000
    state = execute(project, state, SELECT, CTX, CTX+0x1000)
    assert get(state, CTX+0x880) == 0x80225820
    return state


def replay(elf):
    if not __debug__:
        raise RuntimeError('Replay requires assertions')
    import angr
    project = load_project(elf)
    initial = prepare(project, angr)
    results = []
    for name, commands in CASES:
        state, expected, rows = initial.copy(), bytearray([FILL])*(WIDTH*HEIGHT), []
        for command in commands:
            writes = Counter()
            state.globals['branches'], state.globals['cache'] = (), ()

            def branch(st):
                record(st, 'branches', BRANCHES[st.inspect.attrs.instruction])

            def written(st):
                address = concrete(st, st.inspect.attrs.mem_write_address)
                if FRAME <= address < FRAME+WIDTH*HEIGHT:
                    writes[(hex(st.scratch.ins_addr), concrete(st, st.inspect.attrs.mem_write_length))] += 1

            points = [state.inspect.b('instruction', when=angr.BP_BEFORE, instruction=pc, action=branch)
                      for pc in BRANCHES]
            point = state.inspect.b('mem_write', when=angr.BP_BEFORE, action=written)
            state = execute(project, state, DRAW, *command, steps=20000)
            for bp in points: state.inspect.remove_breakpoint('instruction', bp=bp)
            state.inspect.remove_breakpoint('mem_write', bp=point)
            x, y, width, height, color, style = command
            assert style == 0
            chosen = 'word' if width % 32 == 0 and x % 2 == 0 else (
                'halfword' if width % 16 == 0 and x % 2 == 0 else 'gdi')
            assert state.globals['branches'] == (chosen,)
            # This oracle clips only the GDI cases; direct-store fixtures are inside the supplied buffer.
            for row in range(max(0, y), min(HEIGHT, y+height)):
                left, right = max(0, x), min(WIDTH, x+width)
                expected[row*WIDTH+left:row*WIDTH+right] = bytes([color])*(right-left)
            actual = value(state, FRAME, WIDTH*HEIGHT)
            assert actual == expected
            assert value(state, FRAME-8, 8) == value(state, FRAME+WIDTH*HEIGHT, 8) == b'G'*8
            assert list(state.globals['cache']) == ([[FRAME, WIDTH*HEIGHT]] if chosen == 'gdi' else [])
            rows.append(dict(command=command, branch=chosen, frame_sha256=sha256(actual).hexdigest(),
                             changed_bytes=sum(byte != FILL for byte in actual),
                             cache_requests=list(state.globals['cache']),
                             vex_pixel_write_events=[dict(pc=pc, size=size, count=count)
                                                     for (pc, size), count in sorted(writes.items())]))
        results.append(dict(name=name, steps=rows))
    report = dict(analysis_elf_sha256=ELF_SHA256, engine=f'angr {angr.__version__} / VEX',
                  modeled_boundaries=MODELED, buffer=dict(stride=WIDTH, height=HEIGHT, fill=FILL),
                  fixture=FIXTURE,
                  context_fill_function='0x80225820', cases=results)
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__: parser.error('Replay requires assertions')
    if lexists(args.output): parser.error('output must not exist')
    result = replay(args.elf)
    with args.output.open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(f"PASS {len(result['cases'])} original raster fixtures")


if __name__ == '__main__': main()
