"""Replay Q7 Color Space refresh dispatch and indexed focus-marker writes."""
import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct

from check_colorspace_ui import (
    CANVAS, FOCUS, MODELED as UI_MODELED, SETTING, UI_ROOT, WIDGET, call, concrete,
    get, install_hooks, prepare, put, record,
)
from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project
from check_q7_portability import execute, guard, new_state, value


LANGUAGE, SCREEN_MODE, DRAW, SHOW = 0x80B7B32C, 0x80C6AE44, 0x80C6AE84, 0x80C6AE86
REFRESH_REQUEST, UI_PERFORM, REFRESH_RETURN = 0x80AE00F0, 0x80ADF734, 0x80ADF980
QUEUE_SEND, QUEUE_RECEIVE = 0x80125D0C, 0x80125CEC
OSD_CLEAR, OSD_ATTR, OSD_LINE = 0x8043937C, 0x8024BF9C, 0x8043EB54
OSD_TEXT, ALIGNED_TEXT, ICON_DRAW, GET_BUFFER = 0x8024928C, 0x802495D8, 0x8043F42C, 0x80262FD4
CACHE, PUBLISH, DEBUG_LOG = 0x800B3D40, 0x8029EF58, 0x800EC08C
STRIDE, HEIGHT, FRAME = 960, 480, 0x20000000
PIXEL_STRIDE, PIXEL_HEIGHT, DECODED, FILL = 96, 160, 0x20100000, 0xA5
MARKER, ICON_SRC, ICON_BYTES = 0x25, 0x808AEE78, 296
ICON_OFFSET, ICON_FLAG = 0x804A16B0, 0x804A1A24
ICON_W, ICON_H, ICON_NONZERO = 21, 48, 330
LABELS = {
    0x0191D005: 0x8092DAB0, 0x0191D00B: 0x8092D830, 0x0191D010: 0x8092D510,
    0x0191D00D: 0x8092CF08, 0x0191D012: 0x8092C860, 0x0191D014: 0x809B86E8,
    0x0191D019: 0x809B917C,
}
# locale, key edge to offer before refresh, expected selection
CASES = ((0, None, 0), (0, 10, 1), (0, 9, 0), (1, 10, 1))
# Every pair is a count and SHA-256 of a staged line, in native rendering order.
TEXT_LINES = (
    (
        (11, "6f267f04eb0a3b945d58ac879105b63d307d8b241067f29f9a4ca9da3b690a1c"),
        (24, "b818ee54e53b04ce250671672245eec9069981b846ed728cac668a0ed119c9ea"),
        (4, "adda92cf5ff02d3e692ef7a992dad973bf629a47d72e710025f1d46efcd15eca"),
        (8, "49d4516469cee083fe2ee9d9d33a425f039491ed06ec335ce6d2bc43c02e7d1a"),
        (6, "094414b30f0e9e3211c79366bc3b3d87a0647ee4d78d4c0c0295b9f37322663f"),
        (2, "23e0b931f34b64da93ecaa1321fb8c7a57ea99eb8dfa4f0fbd3c26ec2234df61"),
    ),
    (
        (11, "6f267f04eb0a3b945d58ac879105b63d307d8b241067f29f9a4ca9da3b690a1c"),
        (4, "adda92cf5ff02d3e692ef7a992dad973bf629a47d72e710025f1d46efcd15eca"),
        (28, "3178c58620144f1eee556843d2425ce4740c91c611d4cc7613d390b5297f74ac"),
        (8, "49d4516469cee083fe2ee9d9d33a425f039491ed06ec335ce6d2bc43c02e7d1a"),
        (6, "094414b30f0e9e3211c79366bc3b3d87a0647ee4d78d4c0c0295b9f37322663f"),
        (2, "23e0b931f34b64da93ecaa1321fb8c7a57ea99eb8dfa4f0fbd3c26ec2234df61"),
    ),
    (
        (11, "6f267f04eb0a3b945d58ac879105b63d307d8b241067f29f9a4ca9da3b690a1c"),
        (24, "b818ee54e53b04ce250671672245eec9069981b846ed728cac668a0ed119c9ea"),
        (4, "adda92cf5ff02d3e692ef7a992dad973bf629a47d72e710025f1d46efcd15eca"),
        (8, "49d4516469cee083fe2ee9d9d33a425f039491ed06ec335ce6d2bc43c02e7d1a"),
        (6, "094414b30f0e9e3211c79366bc3b3d87a0647ee4d78d4c0c0295b9f37322663f"),
        (2, "23e0b931f34b64da93ecaa1321fb8c7a57ea99eb8dfa4f0fbd3c26ec2234df61"),
    ),
    (
        (15, "aa7ba700da5140c4340835bf9e054723c5020eb64cd2245ef3ddc73b13151b46"),
        (4, "adda92cf5ff02d3e692ef7a992dad973bf629a47d72e710025f1d46efcd15eca"),
        (25, "4fab4a33f949aa74941bca4f2a08d6aa13a995ae5c844e5317e91673ed9e68dc"),
        (12, "ee56a299396d7e1a26721c3b352d4aca24e7aabe3d5ef762f6df2c541740523d"),
        (8, "49d4516469cee083fe2ee9d9d33a425f039491ed06ec335ce6d2bc43c02e7d1a"),
        (7, "47a829d59383257de8aa5d698b7f1aba6889e1e60af4d932e77a6ac07480a9ce"),
        (2, "23e0b931f34b64da93ecaa1321fb8c7a57ea99eb8dfa4f0fbd3c26ec2234df61"),
    ),
)
PIXEL_HASHES = (
    "5f77d98ed9891dc944220270ef4cf7607030d109c92b3e6dc8b46af6fd76ff1d",
    "c691c519295f3c4c43b84d15679b9ed6a5f161ac71e647c240e6fc40e1bc953d",
)
SCOPE = (
    "Original mode 0x53 widget construction/focus, UiService refresh producer and consumer, "
    "widget update/write, text payload staging, solid-line request generation and OSD buffer roll. "
    "Two separate original focus-icon draws compare synthetic indexed-buffer writes byte for byte."
)
MODELED = {
    **{k: UI_MODELED[k] for k in ("0x800ee804", "0x80433354", "0x80adfeb8", "0x80125c24",
                                 "0x809dc650", "0x8024df84")},
    "0x80adfeb8": "Accept initial UI-start request only. Refreshes execute the original SendRequest.",
    "0x80125d0c": "Capture the original 16-byte queue send record and retain it in the fixture.",
    "0x80125cec": "Deliver that exact record once to the native consumer.",
    "0x80125be0": "Accept the outer RTOS event wait.",
    "0x80125f14": "Accept platform mutex lock.",
    "0x80125f98": "Accept platform mutex unlock.",
    "0x80126090": "Accept UI service semaphore acquisition.",
    "0x801260b0": "Accept UI service semaphore release if reached.",
    "0x801049c4": "Return 3 to bypass the unrelated factory-error overlay.",
    "0x8043937c": "Observe OSD clear without clearing a real screen.",
    "0x8024bf9c": "Record native attribute parameters before display-context setters.",
    "0x8043eb54": "Record line geometry and palette parameters before shape rasterization.",
    "0x8043f42c": "Record icon commands during refresh. Restore native implementation for the two isolated marker draws.",
    "0x8024928c": "Copy and hash staged text parameters at AppDBTextOutByBufferID before GDI glyph execution.",
    "0x802495d8": "Reject an unexpected aligned-text branch in these mode 0x53 fixtures.",
    "0x80262fd4": "Return synthetic indexed draw RAM metadata for native roll and isolated marker draws.",
    "0x800b3d40": "Record cache-region address and size without CPU cache operations.",
    "0x8029ef58": "Record native show-buffer request before downstream display-context submission.",
    "0x800ec08c": "Accept the diagnostic log call after show-buffer request.",
}


def frame_commands(y):
    return [[0, y, 720, 6, 77, 0], [0, y, 4, 44, 77, 0],
            [0, y+44, 720, 4, 79, 0], [716, y+4, 4, 44, 79, 0],
            [4, y+4, 712, 40, 78, 0]]


def expected_labels(locale, selected):
    guide = [(0x0191D00D + 5*selected, 32, 280)]
    if locale == 1:
        guide.append((0x0191D012, 32, 328))
    options = [(0x0191D00B, 96, 64), (0x0191D010, 96, 112)]
    return ([(0x0191D005, 80, 0)] + (options[:1] + guide + options[1:] if selected else guide + options)
            + [(0x0191D014, 112, 432), (0x0191D019, 704, 432)])


def reference():
    cases = []
    for i, (locale, key, selected) in enumerate(CASES):
        y = 64 + 48*selected
        draw, show = 17+i%2, 18-i%2
        labels = [dict(widget=widget, xy=[x,y], glyph_units=units, staged_sha256=payload)
                  for (widget,x,y), (units,payload) in zip(expected_labels(locale,selected), TEXT_LINES[i], strict=True)]
        cases.append(dict(locale=locale, key=key, setting=selected, focus_widget=WIDGET[selected],
                          queue_words=[128,1,0,0], refresh_argument=3, solid_line_widget=0x0191D00C+5*selected,
                          frame_commands=frame_commands(y), marker_widget=0x0191D009+5*selected,
                          marker_command=[MARKER,16,y,0,0], text=labels,
                          draw_before=draw, show_before=show, draw_after=show, show_after=draw,
                          cache_range=[FRAME+0x100000*(draw-17), STRIDE*HEIGHT], show_request=[0,draw,1]))
    return dict(analysis_elf_sha256=ELF_SHA256, scope=SCOPE, modeled_boundaries=MODELED,
                refresh_cases=cases, total_text_lines=sum(len(c["text"]) for c in cases),
                pixel_cases=[dict(xy=[16,y], frame_sha256=h, changed_bytes=ICON_NONZERO)
                             for y,h in zip((64,112), PIXEL_HASHES, strict=True)],
                icon=dict(id=MARKER, compressed_va=hex(ICON_SRC), compressed_bytes=ICON_BYTES,
                          compressed_sha256="d9add3441e8fcb4f067fcb8c060803309491bdbf5b79f074c374e5f07ab5df27",
                          decoded_sha256="82c952978c06f71497bab8693e09ab4668ee57a86249a724f13384c851124d51",
                          logical_size=[16,48], bitmap_size=[ICON_W,ICON_H], synthetic_stride=PIXEL_STRIDE,
                          synthetic_height=PIXEL_HEIGHT, initial_palette_index=FILL))


def validate_report(report):
    """Check bounded observations without firmware or third-party imports."""
    engine = report.get("engine")
    if (not isinstance(engine, str) or not engine.startswith("angr ") or not engine.endswith(" / VEX")
            or report != dict(reference(), engine=engine)):
        raise ValueError("Color Space render report differs from the reference")


def set_screen(state):
    state.memory.store(0x80C6AE30, bytes(0x80))
    put(state, SCREEN_MODE, 2)
    put(state, DRAW, 17, 2)
    put(state, SHOW, 18, 2)


def install_render_hooks(project, angr):
    class Send(angr.SimProcedure):
        def run(self, queue, message, timeout):
            assert concrete(self.state, timeout) == 0xFFFFFFFF
            assert "queued" not in self.state.globals
            address = concrete(self.state, message)
            self.state.globals["queued"] = tuple(get(self.state, address+4*i) for i in range(4))
            return 1

    class Receive(angr.SimProcedure):
        def run(self, queue, message, timeout):
            assert concrete(self.state, timeout) == 0xFFFFFFFF
            address = concrete(self.state, message)
            words = self.state.globals.pop("queued")
            self.state.globals["delivered"] = words
            for i, word in enumerate(words):
                put(self.state, address+4*i, word)
            return 1

    class Buffer(angr.SimProcedure):
        def run(self, index, out, width, height):
            state = self.state
            index, out, width, height = [concrete(state, a) for a in (index,out,width,height)]
            assert index in (17,18)
            stride, rows = state.globals.get("frame_size", (STRIDE, HEIGHT))
            state.memory.store(out, struct.pack("<I", FRAME + 0x100000*(index-17)), size=4)
            state.memory.store(width, struct.pack("<H", stride), size=2)
            state.memory.store(height, struct.pack("<H", rows), size=2)
            return 1

    def capture(address, count, result):
        class Observe(angr.SimProcedure):
            def run(self):
                state = self.state
                sp = concrete(state, state.regs.sp)
                args = [concrete(state, getattr(state.regs, f"a{i}")) if i < 4 else get(state, sp+4*i)
                        for i in range(count)]
                if address == ALIGNED_TEXT:
                    raise AssertionError("unexpected aligned text")
                if address == OSD_TEXT:
                    assert args[:2] == [0, 0xFFFF] and args[6] == 1
                    assert 0 < args[5] <= 128 and get(state, args[2], 2) == 1
                    args = dict(widget=state.globals["draw_widget"], xy=args[3:5], glyph_units=args[5],
                                staged_sha256=sha256(value(state,args[2]+2,2*args[5])).hexdigest())
                record(state, address, args)
                return result
        return Observe()

    for address, count, result in ((OSD_CLEAR,0,0), (0x801049C4,0,3), (OSD_ATTR,6,1), (OSD_LINE,6,0),
                                   (ICON_DRAW,5,0), (OSD_TEXT,7,0), (ALIGNED_TEXT,0,0), (CACHE,4,0),
                                   (PUBLISH,3,1), (DEBUG_LOG,2,0), (0x80125BE0,0,1),
                                   (0x80125F14,0,1), (0x80125F98,0,1), (0x80126090,0,1), (0x801260B0,0,1)):
        project.hook(address, capture(address, count, result))
    project.hook(QUEUE_SEND, Send())
    project.hook(QUEUE_RECEIVE, Receive())
    project.hook(GET_BUFFER, Buffer())


def refresh_cases(project, angr):
    state = prepare(project, angr)
    set_screen(state)
    root = get(state, CANVAS)
    state, _ = call(project, state, 0x80A8BA08, 0x10000000, 0x53)
    assert get(state, UI_ROOT) == root
    state, _ = call(project, state, 0x80AC9050, 0xFFFF)
    state, _ = call(project, state, 0x80AC8524, root)
    state, _ = call(project, state, 0x80AC8F78, 1)
    project.unhook(0x80ADFEB8)

    def entering(state):
        component = concrete(state, state.regs.a2)
        state.globals["draw_widget"] = get(state, component+4)
        if state.addr != 0x80AD24EC:
            record(state, state.addr, state.globals["draw_widget"])

    def consumer(state):
        record(state, "refresh_arguments", concrete(state, state.regs.a0))

    for address in (0x80AD24EC, 0x80AD92D0, 0x80ACE028):
        state.inspect.b("instruction", when=angr.BP_BEFORE, instruction=address, action=entering)
    state.inspect.b("instruction", when=angr.BP_BEFORE, instruction=0x80ADF300, action=consumer)
    result = []
    for locale, key, selected in CASES:
        if key is not None:
            state, consumed = call(project, state, 0x80AC8594, key, root)
            assert consumed == 1
        put(state, LANGUAGE, locale)
        before = get(state, DRAW, 2), get(state, SHOW, 2)
        state, status = call(project, state, REFRESH_REQUEST, 1)
        assert status == 1
        state.regs.pc, state.regs.ra = UI_PERFORM, RETURN_PC
        sim = project.factory.simgr(state, save_unconstrained=True)
        sim.explore(find=REFRESH_RETURN, n=9000)
        assert len(sim.found) == 1 and not sim.active and not sim.errored and not sim.unconstrained, sim.errored
        state = sim.found[0]
        assert concrete(state, state.regs.sp) == STACK_TOP - 0xC8
        # The RTOS service is a loop. Stop after one dispatched refresh and reuse its RAM.
        state.regs.sp = STACK_TOP
        observed = list(state.globals.pop(OSD_TEXT))
        assert [(row["widget"], *row["xy"]) for row in observed] == expected_labels(locale, selected)
        for row, expected in zip(observed, source_lines(project, locale, observed), strict=True):
            assert (row["glyph_units"], row["staged_sha256"]) == expected
        y = 64+48*selected
        shapes = list(state.globals.pop(OSD_LINE))
        marker, = [entry for entry in state.globals.pop(ICON_DRAW) if entry[0] == MARKER]
        assert len(state.globals.pop(OSD_CLEAR)) == 1
        refresh_args = state.globals.pop("refresh_arguments")
        assert refresh_args == (3,), (refresh_args, state.globals["delivered"])
        cache, = state.globals.pop(CACHE)
        show, = state.globals.pop(PUBLISH)
        solid, = state.globals.pop(0x80AD92D0)
        marker_widget = 0x0191D009 + 5*selected
        assert marker_widget in state.globals.pop(0x80ACE028)
        state.globals.pop(OSD_ATTR)
        assert shapes[3:] == frame_commands(y)
        result.append(dict(locale=locale, key=key, setting=get(state, SETTING, 1),
                           focus_widget=get(state, FOCUS), queue_words=list(state.globals.pop("delivered")),
                           refresh_argument=3, solid_line_widget=solid, frame_commands=shapes[3:],
                           marker_widget=marker_widget, marker_command=marker, text=observed,
                           draw_before=before[0], show_before=before[1], draw_after=get(state,DRAW,2),
                           show_after=get(state,SHOW,2), cache_range=cache[:2], show_request=show))
    return result


def source_lines(project, locale, records):
    """Independently read each source descriptor and original glyph-index bytes."""
    load = project.loader.memory.load
    u32 = lambda address: struct.unpack("<I", load(address,4))[0]
    current = None
    for record in records:
        widget = record["widget"]
        if widget != current:
            if current is not None:
                assert line == count
            desc = u32(LABELS[widget]+4*locale)
            count = load(desc,1)[0]
            lengths, pointers = u32(desc+4), u32(desc+8)
            line, current = 0, widget
        assert line < count
        n = load(lengths+line,1)[0]
        yield n, sha256(load(u32(pointers+4*line),2*n)).hexdigest()
        line += 1
    assert line == count


def pixel_cases(project, angr):
    project.unhook(ICON_DRAW)
    packed = project.loader.memory.load(ICON_SRC, ICON_BYTES)
    pixels = b"".join(bytes([index])*count for index,count in zip(packed[::2],packed[1::2],strict=True))
    assert len(pixels) == ICON_W*ICON_H and sum(i != 0 for i in pixels) == ICON_NONZERO
    results = []
    size = PIXEL_STRIDE*PIXEL_HEIGHT
    for y in (64,112):
        state = new_state(project, angr)
        set_screen(state)
        state.globals["frame_size"] = (PIXEL_STRIDE, PIXEL_HEIGHT)
        put(state, 0x804A161C, DECODED)
        put(state, ICON_OFFSET, 0)
        put(state, ICON_FLAG, 0, 1)
        state.memory.store(DECODED, bytes([FILL])*(len(pixels)+8))
        state.memory.store(FRAME, bytes([FILL])*size)
        ram = ((ICON_FLAG,ICON_FLAG+1), (DECODED,DECODED+len(pixels)), (FRAME,FRAME+size))
        readonly = ((0x804A161C,0x804A1620), (ICON_OFFSET,ICON_OFFSET+4),
                    (0x80C6AE30,0x80C6AEB0), (0x804E86AC,0x804E86D0),
                    (0x808A786C,0x808A821C), (ICON_SRC,ICON_SRC+ICON_BYTES))
        guard(state, angr, ram, readonly)
        state = execute(project, state, ICON_DRAW, MARKER, 16, y, 0, 0, steps=9000)
        expected = bytearray([FILL])*size
        for i,index in enumerate(pixels):
            if index:
                row,col = divmod(i,ICON_W)
                expected[(y+row)*PIXEL_STRIDE+16+col] = index
        assert value(state, DECODED, len(pixels)+8) == pixels + bytes([FILL])*8
        assert value(state, ICON_FLAG, 1) == b"\x01"
        actual = value(state, FRAME, size)
        assert actual == expected
        results.append(dict(xy=[16,y], frame_sha256=sha256(actual).hexdigest(),
                            changed_bytes=sum(v != FILL for v in actual)))
    return results


def replay(elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    import angr
    project = load_project(elf)
    install_hooks(project, angr)
    install_render_hooks(project, angr)
    refresh = refresh_cases(project, angr)
    pixels = pixel_cases(project, angr)
    result = dict(reference(), refresh_cases=refresh, pixel_cases=pixels, engine=f"angr {angr.__version__} / VEX")
    validate_report(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if lexists(args.output):
        parser.error("output must not exist")
    result = replay(args.elf)
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    print(f"PASS {len(result['refresh_cases'])} refresh dispatches, {result['total_text_lines']} text lines, "
          f"{len(result['pixel_cases'])} indexed focus-marker draws")


if __name__ == "__main__":
    main()

