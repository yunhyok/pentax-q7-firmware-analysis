"""Replay bounded Q7 glyph clipping or check the published evidence without assets."""

import argparse
from collections import Counter
from hashlib import sha256
import io
import json
from os.path import lexists
from pathlib import Path
import struct
import sys
import types

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_SIZE, ELF_SIZE = 18743520, 12504100
PACKAGE_SHA = '8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b'
ELF_SHA = 'a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796'
E04_BASE = 0x8012DA80
E04_SHA = 'e7d06ec99f6e95025721b62d42f39845a2f2277991f4dfcabc3e3f930ff5bd5b'
SOURCE_PINS = {
    'tools/check_colorspace_attributes.py': '4c4f24cc88582f9db58318bca674999dc3199c1b32f439ea98ed57e118d3ebc1',
    'tools/check_colorspace_glyph.py': 'cc5a69d3a826a0a81137806e5eab44562c7904c2201023067f142340ea6480e2',
    'tools/check_colorspace_raster.py': 'ad0127dca8888364653837d6072097b7a0b52d63dc1f40ba6523974772694e29',
    'tools/check_colorspace_render.py': '3fc8175f5a90236a24b24887097d5aa4ce04d02f9167f3b984e8a81fc7339607',
    'tools/check_colorspace_ui.py': 'cfc5d3ffed73cd9e420e95813c7b2bfd86f2279be25f2fc620b2f5de2242cb64',
    'tools/check_isp_registers.py': 'f04d12f97d55624ffab5fa59eddf8bce8b2900d7ef3127bd30761ae7d074cf92',
    'tools/check_q7_portability.py': '63d52486e6979a15520e97cf33c003f897dae7fbcce4dde08011dce265706af7',
    'tools/q7_symbols.py': '2b1e228deee232cc7b78ed347cf7319bed711ce1e54dc1bbfc1e63de4e3f0ec7',
    'tools/inspect_q7.py': '3e8df227d9bf96c6b2bdbd20433e2c80a1d80019d05c0778d978736c606bc2b8',
    'tools/pentax_lz.py': '5a8a60bdbaf7be7c5acead0ab04877b93a3c6e753e8b8f332281974f36c3b6bf',
    'tools/decode_segments.py': 'fdad9e9abbbd4dfe1ee36bdf340ac8cbd5cea9064d5345ab32165c78dd12ba9d',
    'analysis/colorspace-attributes.json': '7604d1cb9649e705b8bb6f2a381841c3bf183eac3268432cac5a5bff0dba5305',
    'analysis/context-binding.json': '06202757da1b222f384ea79188d64f23f3f8625c2dea097ec8881303948ec3ec',
}

# Q7-TEXT-CLIP-43 used raw Windows worktree hashes. Keep those two raw
# identities in its witness schema, separate from the portable execution pins.
RECORDED_SOURCE_PINS = {
    **SOURCE_PINS,
    'tools/check_colorspace_attributes.py': 'f7dfefb0929985c9027fba38742df02d2d827026c436ba423c6cd4404f1601a4',
    'tools/decode_segments.py': '050993664b956416f2d85a9dc98cdfa45646fb0a2834018217e41f3e5629220a',
}
STAGES = {
    'edges': (
        ('interior', 96, 64), ('left', -9, 64), ('right', 725, 64),
        ('top', 96, -19), ('bottom', 96, 157), ('upper-left', -9, 0),
    ),
    'corner': (('upper-left-painted', -9, -12),),
}
FULL_WITNESS_PINS = {
    'edges': '9c8f96829c1b4c57bf6f535ab2890246cc5036a74c92647718fb554e3f77bc7c',
    'corner': '6a9b411c16e56bb102da1c1f70f7f58ab41d19c2585eccb45e4711beea237444',
}
FROZEN_PRIVATE_PINS = {
    'edges': {
        'probe_sha256': '13cf1a60decaca93a1026afa2c62e80b99247c120126ec7a3e4fea00a73e6e7b',
        'recording_sha256': '1b765693a7ba808fe092824cac251e54d1e3d7f11b7fc02013692507cae4da8a',
    },
    'corner': {
        'probe_sha256': 'f80d9459ece12005e557f967a4480ed42e70f72d71b92a7dcc4594545ff0a70c',
        'recording_sha256': 'e2aa6d1662eccf0fe52a7bf7d3938f2f409c9a1362ba51393e6c5954f237c3bd',
    },
}
PUBLIC_PIN = '7e58bd64c0b7025202dd187c51db89e37b972863aed0aa2c0c7f33bfbc01b0f6'
MAX_INSNS = 800_000
MODELED_PC = (0x8000BF28, 0x80262FD4, 0x800B3D40, 0x80240E2C, 0x8007D180,
              0x80074334, 0x80071A10, 0x8007C258, 0x8000C598, 0x800A14F8)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(',', ':')).encode()

def bounded_bytes(path, cap):
    with path.open('rb') as stream:
        data = stream.read(cap+1)
    require(len(data) <= cap, f'input exceeds size limit: {path.name}')
    return data


def capture(path, size, expected):
    raw = bounded_bytes(path, size)
    require(len(raw) == size and digest(raw) == expected, f'input identity: {path.name}')
    return raw


def capture_sources(repository):
    # The repository declares eol=lf. Hash and execute the same normalized bytes.
    captured = {}
    for path, pin in SOURCE_PINS.items():
        source = bounded_bytes(repository/path, 512_000).replace(b'\r\n', b'\n')
        require(digest(source) == pin, f'captured source identity: {path}')
        captured[path] = source
    modules = (
        'pentax_lz', 'inspect_q7', 'q7_symbols', 'decode_segments',
        'check_isp_registers', 'check_q7_portability', 'check_colorspace_ui',
        'check_colorspace_render', 'check_colorspace_raster', 'check_colorspace_glyph',
        'check_colorspace_attributes',
    )
    require(not set(modules).intersection(sys.modules), 'project helpers already imported')
    for name in modules:
        path = f'tools/{name}.py'
        module = types.ModuleType(name)
        module.__file__ = str(repository/path)
        sys.modules[name] = module
        exec(compile(captured[path], module.__file__, 'exec', dont_inherit=True), module.__dict__)
    return json.loads(captured['analysis/colorspace-attributes.json'])['bounded_replay']

def segments_from_elf(elf_bytes):
    from elftools.elf.elffile import ELFFile
    elf = ELFFile(io.BytesIO(elf_bytes))
    return tuple((int(seg['p_vaddr']),seg.data()) for seg in elf.iter_segments()
                 if seg['p_type'] == 'PT_LOAD')


def verify_e04(package, segments):
    from decode_segments import decode_segment
    from inspect_q7 import parse_elf
    entry, _ = parse_elf(package, 0x2402C0)
    segment, = [s for s in entry['segments'] if s['type'] == 1]
    body, blocks = decode_segment(package, segment)
    elf_body, = [body for va,body in segments if va == E04_BASE]
    require(len(blocks) == 178 and digest(body) == E04_SHA and body == elf_body, 'original E04 identity')
    return body


def resource_glyphs(blob, units):
    def word(offset):
        return struct.unpack_from('<I', blob, offset)[0]

    require(blob[:10] == b'LatinFont\0' and word(0x20) == 0x202, 'font header')
    require((word(0x24),word(0x2C),blob[0x37]) == (64,48,2), 'font dimensions')
    ranges, widths, maps = (word(offset) for offset in (0x40,0x44,0x4C))
    require(word(ranges+0x14) == 1, 'one source glyph range')
    desc = ranges+0x18
    first, limit = word(desc+0x20),word(desc+0x24)
    require((first,limit) == (0,0xAA), 'font glyph range')
    for unit in units:
        require(first <= unit <= limit, 'glyph ID range')
        index = unit-first
        width = blob[widths+word(desc+0x18)+index]
        offset = maps+2*word(desc+0x14)+index*16*48
        require(0 < width <= 64 and offset+16*48 <= len(blob), 'packed glyph bounds')
        yield width,offset


def oracle(blob, glyph, attrs, origin):
    width,height,palette = glyph.WIDTH,glyph.HEIGHT,glyph.CONTEXT['pixel_indices']
    frame = bytearray([glyph.FILL]) * (width*height)
    x,y = origin
    stores, samples, calls, q16 = [], [], [], []
    excluded = Counter()
    for i,(source_width,offset) in enumerate(list(resource_glyphs(blob, attrs.UNITS))[:1]):
        factor = (48*65536)//64
        dest_width = (source_width*factor)//65536
        step = (source_width*65536)//dest_width
        columns = [(col*step+step//2)//65536 for col in range(dest_width)]
        calls.append([glyph.CTX,glyph.FONT+offset,64,x,y,source_width,48,dest_width,48])
        q16.append(dict(unit=attrs.UNITS[i], source_width=source_width, dest_width=dest_width,
                        font_offset=offset, step=step, source_columns=columns))
        for row in range(48):
            row_start = (y+row)*width+x
            for col, source_col in enumerate(columns):
                packed = blob[offset+row*16+source_col//4]
                code = (packed >> (6-2*(source_col%4))) & 3
                samples.append([i,row,col,source_col,code])
                # The outer check is on the row-start address, prior to x+column.
                # Each individual edge avoids wrapping a row-start at the far edge.
                if not 0 <= row_start < len(frame):
                    excluded['row_start'] += 1
                elif not 0 <= x+col < width:
                    excluded['column'] += 1
                elif not code:
                    excluded['transparent_zero'] += 1
                else:
                    position = row_start+col
                    require(0 <= position < len(frame), 'oracle store outside prepared surface')
                    frame[position] = palette[code]
                    stores.append([position,palette[code]])
        x += dest_width
    return frame, stores, samples, calls, q16, dict(excluded)


def prepare(package, elf_bytes, evidence):
    import angr
    import check_colorspace_attributes as attrs
    from check_colorspace_ui import get
    from check_q7_portability import value
    glyph = attrs.glyph
    project = angr.Project(io.BytesIO(elf_bytes), auto_load_libs=False)
    attrs.validate_report(evidence)
    blob = glyph.read_font(package)
    initial, loader = glyph.prepare_font(project, angr, blob)
    require(glyph.digest(loader) == glyph.LOADER_SHA256, 'existing native font loader witness')
    captured = [r['args'] for r in evidence['refresh']['srgb_groups'][0][:3]]
    configured, snapshots = attrs.apply_attributes(project, initial, captured)
    require(snapshots == evidence['dispatch'][1]['context_snapshots'], 'existing native setter witness')
    attrs.stage(configured)
    segments = [
        ('context',glyph.CTX,0x8B0), ('bitmap',glyph.CTX+0x1000,12),
        ('registry',glyph.TABLE,0x100), ('font',glyph.FONT,len(blob)), ('text',glyph.TEXT,12),
        ('screen',0x80C6AE30,0x80), ('default_context',0x800EB4D8,4),
        ('color_control',0x800EBD70,4), ('registry_pointer',0x8029F340,4),
    ]
    seed = {name:(va,value(configured,va,n)) for name,va,n in segments}
    require([get(configured,glyph.CTX+i,1) for i in (0x830,0x831,0x83C,0x84C,0x84D)] == [0,1,1,0,0],
            'existing orientation/transparent configuration')
    require(get(configured,glyph.CTX+0x868) == 0 and get(configured,glyph.CTX+0x894) == attrs.STRETCH,
            'no auxiliary clipping bitmap and correct stretch entry')
    return angr.__version__, glyph, attrs, blob, loader, captured, seed, project, configured


def replay_one(project, configured, segments, glyph, attrs, name, origin, predicted):
    import angr
    from check_colorspace_ui import concrete, get
    from check_q7_portability import execute, value
    expected_frame, expected_stores, expected_samples, expected_calls, q16, exclusions = predicted
    frame_size = glyph.WIDTH*glyph.HEIGHT
    end = glyph.FRAME+frame_size
    guard = b'\x97\x31\xca\x58\x0d\xbf\x74\x23' * 2
    state = configured.copy()
    state.memory.store(glyph.FRAME-len(guard),guard,inspect=False)
    state.memory.store(end,guard,inspect=False)
    font_before = value(state,glyph.FONT,glyph.FONT_SIZE)
    stage_before = value(state,glyph.TEXT,12)
    context_before = value(state,glyph.CTX,0x8B0)
    observed_stores, observed_samples, observed_calls = [], [], []
    key_pcs = Counter()
    executed = set()
    instruction_trace = sha256()
    insn_count = 0
    current = None
    expected_frame_start = glyph.FRAME
    code_regions = [(va,va+len(raw),raw) for va,raw in segments if va in (0x80000780,E04_BASE)]
    def source(va,size):
        for lo,hi,raw in code_regions:
            if lo <= va < va+size <= hi: return raw[va-lo:va-lo+size]
        raise ValueError(f"unapproved execution boundary {va:#x}")
    def reg(st, name):
        return concrete(st,getattr(st.regs,name))
    def signed(n):
        return n if n < 0x80000000 else n-(1<<32)
    def instruction(st):
        nonlocal current,insn_count
        va = st.inspect.attrs.instruction
        insn_count += 1
        require(insn_count <= MAX_INSNS,'native instruction cap')
        require((E04_BASE <= va <= E04_BASE+0x3f2300-4 or 0x800fbd60 <= va < 0x800fbe80) and va not in MODELED_PC,
                f'unapproved execution boundary {va:#x}')
        # The project was made from the captured immutable bytes. VEX fetches
        # that original image, and the RAM guard rejects writes to it.
        executed.add(va)
        instruction_trace.update(struct.pack('<I',va)+source(va,4))
        if va in (0x80226748,0x80226a5c,0x80226a78,0x80226a8c,0x80226a94,0x80226c5c):
            key_pcs[f'{va:#x}'] += 1
        if va == attrs.STRETCH:
            args = attrs.arguments(st,9)
            args[3:5] = list(map(signed,args[3:5]))
            current = args[1]
            observed_calls.append(dict(ra=f"{reg(st,'ra'):#x}",args=args))
        if va == 0x80226a5c:
            row = get(st,reg(st,'sp')+0x28)
            packed_cursor = reg(st,'t5')
            shift = (reg(st,'t8')+2)&255
            word_index,remainder = divmod(packed_cursor-current-row*16,2)
            require(not remainder and 0 <= shift <= 14 and shift%2 == 0 and 1 <= word_index <= 8,
                    f'{name}: packed cursor {packed_cursor:#x}, row {row}, shift {shift}')
            source_column = (word_index-1)*8+(14-shift)//2
            observed_samples.append([len(observed_calls)-1,row,reg(st,'s2'),source_column,reg(st,'s4')])
    def write(st):
        a = st.inspect.attrs
        address = concrete(st,a.mem_write_address)
        if expected_frame_start <= address < end:
            require(concrete(st,a.mem_write_length) == 1 and st.scratch.ins_addr == 0x80226c5c,
                    f'{name}: unexpected frame store at {st.scratch.ins_addr:#x}')
            observed_stores.append([address-expected_frame_start,concrete(st,a.mem_write_expr)])
    state.inspect.b('instruction',when=angr.BP_BEFORE,action=instruction)
    state.inspect.b('mem_write',when=angr.BP_BEFORE,action=write)
    args = expected_calls[0]
    final = execute(project,state,attrs.STRETCH,*args,steps=25000)
    require(observed_calls == [dict(ra=f'{attrs.RETURN_PC:#x}',args=args) for args in expected_calls],
            f'{name}: actual stretch calls differ: {observed_calls}')
    for label, actual, expected in [('source columns/codes',observed_samples,expected_samples),
                                    ('ordered surface writes',observed_stores,expected_stores)]:
        if actual != expected:
            index = next((i for i,(a,b) in enumerate(zip(actual,expected)) if a != b), min(len(actual),len(expected)))
            raise ValueError(f'{name}: {label} {len(actual)}/{len(expected)} first diff {index}: '
                             f'{actual[index:index+2]} vs {expected[index:index+2]}')
    actual = value(final,glyph.FRAME,frame_size)
    require(actual == expected_frame, f'{name}: whole frame mismatch')
    require(value(final,glyph.FRAME-len(guard),len(guard)) == value(final,end,len(guard)) == guard,
            f'{name}: frame canaries')
    require(value(final,glyph.FONT,glyph.FONT_SIZE) == font_before
            and value(final,glyph.TEXT,12) == stage_before, f'{name}: input changed')
    changed_context = [i for i,(a,b) in enumerate(zip(context_before,value(final,glyph.CTX,0x8B0),strict=True)) if a != b]
    require(all(0x24 <= i < 0x34 for i in changed_context), f'{name}: unexpected context changes {changed_context}')
    spans = []
    for va in sorted(executed):
        if spans and spans[-1][1] == va:
            spans[-1][1] += 4
        else:
            spans.append([va,va+4])
    pinned_spans = [dict(start=f'{a:#x}',end_exclusive=f'{b:#x}',segment='E04' if a >= E04_BASE else 'E03', segment_offset=f'{a-(E04_BASE if a >= E04_BASE else 0x80000780):#x}',
                         sha256=digest(source(a,b-a))) for a,b in spans]
    return dict(name=name, origin=list(origin), returned=True, calls=observed_calls, q16=q16,
                frame_sha256=digest(actual), frame_oracle_equal=True, canaries_per_end=len(guard),
                changed_bytes=sum(x != glyph.FILL for x in actual), store_count=len(observed_stores),
                stores_sha256=digest(canonical(observed_stores)), sample_count=len(observed_samples),
                samples_sha256=digest(canonical(observed_samples)), rejected_candidates=exclusions,
                histogram={str(i):n for i,n in sorted(Counter(actual).items())}, gate_hits=dict(sorted(key_pcs.items())),
                changed_context_offsets=changed_context, instruction_events=insn_count,
                instruction_trace_sha256=instruction_trace.hexdigest(), executed_spans=pinned_spans)

def require_witness(stage, witness):
    require(digest(canonical(witness)) == FULL_WITNESS_PINS[stage],
            f'{stage}: complete typed native witness differs')


def replay(package, elf_bytes, evidence, stage):
    segments = segments_from_elf(elf_bytes)
    verify_e04(package, segments)
    engine, glyph, attrs, blob, loader, captured, seed, project, configured = prepare(package, elf_bytes, evidence)
    require(engine == '10.0.5', 'expected angr 10.0.5')
    cases = []
    for name,x,y in STAGES[stage]:
        predicted = oracle(blob, glyph, attrs, (x,y))
        result = replay_one(project, configured, segments, glyph, attrs, name, (x,y), predicted)
        cases.append(result)
        print(f"{name}: {result['store_count']} stores, frame {result['frame_sha256']}", flush=True)
    witness = dict(
        schema='q7-text-clip43-v1', input_sha256=PACKAGE_SHA, elf_sha256=ELF_SHA, e04_sha256=E04_SHA,
        sources=RECORDED_SOURCE_PINS, font_sha256=digest(blob), stage_units=[attrs.UNITS[0]],
        model_setup=glyph.MODELED, loader_events=loader, captured_attrs=captured,
        engine=dict(setup=f'angr {engine} / VEX', draw=f'angr {engine} / VEX'),
        surface=dict(pitch=glyph.WIDTH, height=glyph.HEIGHT, format='8-bit indexed',
                     fill=glyph.FILL, initial_index_map=glyph.CONTEXT['pixel_indices']),
        snapshot_sha256={name:digest(data) for name,(va,data) in seed.items()},
        native_draw_entry=f'{attrs.STRETCH:#x}', stop=f'{attrs.RETURN_PC:#x}', draw_model_calls=0,
        draw_instruction_cap=MAX_INSNS, cases=cases,
    )
    require_witness(stage, witness)
    return witness


def project(edges, corner):
    # Neither stage can be projected until both complete typed witnesses match.
    require_witness('edges', edges)
    require_witness('corner', corner)
    observations = []
    for case in edges['cases'] + corner['cases']:
        keys = ('name', 'origin', 'returned', 'canaries_per_end', 'sample_count',
                'samples_sha256', 'store_count', 'stores_sha256', 'frame_sha256',
                'gate_hits', 'rejected_candidates', 'histogram', 'instruction_events',
                'instruction_trace_sha256', 'changed_context_offsets')
        row = {key:case[key] for key in keys}
        row['complete_case_sha256'] = digest(canonical(case))
        row['executed_span_count'] = len(case['executed_spans'])
        row['executed_spans_sha256'] = digest(canonical(case['executed_spans']))
        observations.append(row)
    shared = ('input_sha256','elf_sha256','e04_sha256','font_sha256','stage_units',
              'model_setup','captured_attrs','engine','surface','snapshot_sha256',
              'native_draw_entry','draw_model_calls','draw_instruction_cap')
    return dict(
        schema='q7-colorspace-clip-v1',
        **{key:edges[key] for key in shared},
        host_return_sentinel=edges['stop'],
        source_revision='77dfa9db8b9a93ed1e413a157ccba8595141fd24',
        source_pins_lf=SOURCE_PINS,
        recorded_private_sources_raw=FROZEN_PRIVATE_PINS,
        complete_typed_witness_sha256=FULL_WITNESS_PINS,
        font_selection=dict(color_space_row_first_code=84, source_cell=[64,48],
                            requested_cell=[48,48], glyph=edges['cases'][0]['q16'][0]),
        source_ranges=[
            dict(start='0x8022684c',end_exclusive='0x802268c0',e04_offset='0xf8dcc',
                 sha256='576d34f4a01dc8cfa409fdc00125794159cb21caa791598fd01014d8022c570c'),
            dict(start='0x802269b4',end_exclusive='0x802269c0',e04_offset='0xf8f34',
                 sha256='3a82cd7e4bcd325b008e212fe22cdd912d014c7d20faa94dd451a66d63809e7d'),
            dict(start='0x80226a5c',end_exclusive='0x80226a94',e04_offset='0xf8fdc',
                 sha256='3875974dde97e31959da02953e240e72dc41f8d338e852daf5b1fa2247bc355f'),
            dict(start='0x80226a94',end_exclusive='0x80226abc',e04_offset='0xf9014',
                 sha256='33325e681e796e6b8a85c731137e8f05121843e9c3e801449b86fd2c3f985e2d'),
            dict(start='0x80226c54',end_exclusive='0x80226cb4',e04_offset='0xf91d4',
                 sha256='1d01f10fab8dc0c6d74e6b23f60c9057a56945cbda552d3e0a5c71a166eefa38'),
        ],
        rectangular_counterexample=dict(case='upper-left-painted', source_row=12, destination_row=0,
                                        glyph_row_start_relative_to_frame=-9, visible_x_inclusive=[0,7],
                                        ordinary_rectangle_store_count=228, original_store_count=220,
                                        skipped_index_count=8, retained_fill=165),
        independent_review=dict(replayed_native_cases=['upper-left-painted'],
                                compared_original_recordings=['interior','left','right','top','bottom','upper-left'],
                                executed_span_records_rehashed=224, source_opcode_words_rechecked=217),
        scope=dict(draw='Separate original stretch calls in a synthetic indexed buffer with supplied origins.',
                   setup='Original context, font and attribute setup with the enumerated service models and synthetic ID 0/17 alias.',
                   limits='Actual menu edge coordinates, alternate orientation or scale modes, LCD output and a firmware UI port are unverified.'),
        cases=observations,
    )


def read_json(path):
    return json.loads(bounded_bytes(path, 512_000))


def write_new(path, value):
    payload = json.dumps(value, ensure_ascii=False, indent=2)+'\n'
    with path.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(payload)


def validate_public(doc):
    require(digest(canonical(doc)) == PUBLIC_PIN, 'published evidence differs')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    native = sub.add_parser('replay', help='run one original VEX stage and save its complete witness')
    native.add_argument('firmware', type=Path)
    native.add_argument('elf', type=Path)
    native.add_argument('--repository', type=Path, default=ROOT)
    native.add_argument('--stage', required=True, choices=tuple(STAGES))
    native.add_argument('--output', required=True, type=Path)
    compact = sub.add_parser('project', help='validate both complete witnesses and produce the public summary')
    compact.add_argument('edges', type=Path)
    compact.add_argument('corner', type=Path)
    compact.add_argument('--output', required=True, type=Path)
    check = sub.add_parser('check', help='check the recorded public summary without firmware or emulation')
    check.add_argument('evidence', type=Path, nargs='?', default=ROOT/'analysis/colorspace-clip.json')
    args = parser.parse_args(argv)
    if not __debug__:
        parser.error('replay requires assertions')
    if getattr(args, 'output', None) is not None and lexists(args.output):
        parser.error('output must not exist')
    if args.command == 'check':
        validate_public(read_json(args.evidence))
        print('PASS recorded Q7 clipping evidence (7 cases; no emulation)')
        return
    if args.command == 'project':
        public = project(read_json(args.edges), read_json(args.corner))
        validate_public(public)
        write_new(args.output, public)
        print('PASS complete typed witnesses before projection (7 cases)')
        return
    package = capture(args.firmware, PACKAGE_SIZE, PACKAGE_SHA)
    elf = capture(args.elf, ELF_SIZE, ELF_SHA)
    evidence = capture_sources(args.repository.resolve())
    write_new(args.output, replay(package, elf, evidence, args.stage))
    print(f'PASS {args.stage} complete native witness')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        raise SystemExit(str(error))
