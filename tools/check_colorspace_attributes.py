"""Capture Color Space font attributes and replay one scaled indexed text draw."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct

import check_colorspace_glyph as glyph
import check_colorspace_render as render
from check_colorspace_ui import concrete, get
from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project
from check_q7_portability import execute, value
from q7_symbols import SHA


WIDGET = 0x0191D00B
STRETCH = 0x80226748
UNITS = (84, 51, 40, 35)
TEXT_BYTES = struct.pack("<4H", *UNITS)
DISPATCH_CAP, SCALE_CAP = 5000, 150000
BINDING = "Synthetic default ID0 and captured attribute ID17 share the selected 8-bit context"
MODELED = {"refresh": render.MODELED, "staged": glyph.MODELED}
EVENT_SHA256 = "2e8a9f3ea98670c10d59087ff45d97af2e2d9674ee86424c3883b3c3dd0de9de"
DISPATCH_SHA256 = (
    "511d404be7c15de5b0e602a542faa318aeaa6a4a25acb6942f27450e5ae9f2d4",
    "98f1e17c76e97aee245a0238cd4b7d5f7ad88b35695d189d0cd7015f3be92429",
)
SCALE_SHA256 = "a6dd63807a29450838e78270534587a5e4a7d3b8da1748353ea1be3f7ac9f43c"


def arguments(state, count):
    sp = concrete(state, state.regs.sp)
    return [concrete(state, getattr(state.regs, f"a{i}")) if i < 4 else get(state, sp+4*i)
            for i in range(count)]


def summarize_refresh(cases, events):
    selected = [events[i-3:i+1] for i, row in enumerate(events)
                if row["kind"] == "text" and row["widget"] == hex(WIDGET)]
    return dict(case_count=len(cases), prior_refresh_sha256=glyph.digest(cases),
                event_counts=dict(Counter(row["kind"] for row in events)),
                ordered_event_sha256=glyph.digest(events), srgb_groups=selected)


def expected_refresh():
    groups = []
    for draw_id in (17, 18, 17, 18):
        rows = [dict(kind="attribute", widget=hex(WIDGET), return_address="0x8029ea5c",
                     args=[draw_id, *tail]) for tail in ([7,48,48,0,0], [12,0,0,0,0], [4,2,0,0,0])]
        rows.append(dict(kind="text", widget=hex(WIDGET), return_address="0x802493ec",
                         args=[0,0xFFFF,0x70000D28,96,64,4,1],
                         staged_sha256=sha256(TEXT_BYTES).hexdigest()))
        groups.append(rows)
    return dict(case_count=4, prior_refresh_sha256=glyph.digest(render.reference()["refresh_cases"]),
                event_counts={"attribute":72,"text":25}, ordered_event_sha256=EVENT_SHA256, srgb_groups=groups)


def capture_refresh(project, angr):
    events = []

    class Observe(angr.SimProcedure):
        def run(self, *, address):
            state = self.state
            is_text = address == render.OSD_TEXT
            args = arguments(state, 7 if is_text else 6)
            widget = state.globals.get("draw_widget")
            row = dict(kind="text" if is_text else "attribute",
                       widget=hex(widget) if widget is not None else None,
                       return_address=hex(concrete(state,state.regs.ra)), args=args)
            observation = args
            if is_text:
                assert args[:2] == [0,0xFFFF] and args[6] == 1
                assert 0 < args[5] <= 128 and get(state,args[2],2) == 1
                row["staged_sha256"] = sha256(value(state,args[2]+2,2*args[5])).hexdigest()
                observation = dict(widget=widget, xy=args[3:5], glyph_units=args[5],
                                   staged_sha256=row["staged_sha256"])
            render.record(state,address,observation)
            events.append(row)
            return int(not is_text)

    render.install_hooks(project,angr)
    render.install_render_hooks(project,angr)
    for address in (render.OSD_ATTR,render.OSD_TEXT):
        project.hook(address,Observe(num_args=0,address=address),replace=True)
    cases = render.refresh_cases(project,angr)
    assert cases == render.reference()["refresh_cases"]
    summary = summarize_refresh(cases,events)
    assert summary == expected_refresh()
    return summary


def context_fields(state):
    return dict(font_extent=[get(state,glyph.CTX+i,2) for i in (0x82C,0x82E)],
                spacing=[get(state,glyph.CTX+i) for i in (0x824,0x828)],
                palette=[get(state,glyph.CTX+i) for i in (0x24,0x28,0x2C,0x30)],
                transparent_mode=get(state,glyph.CTX+0x83C,1))


def apply_attributes(project, state, requests):
    snapshots = [dict(after=None, fields=context_fields(state))]
    for params in requests:
        state = execute(project,state,render.OSD_ATTR,*params)
        assert concrete(state,state.regs.v0) == 1
        snapshots.append(dict(after=params, fields=context_fields(state)))
    return state,snapshots


def stage(state):
    state.memory.store(glyph.TEXT,b"\x01\x00"+TEXT_BYTES+b"\0\0",inspect=False)
    return (0,0xFFFF,glyph.TEXT,*glyph.CONTEXT["origin"],len(UNITS),1)


def block_count(state):
    return len(list(state.history.bbl_addrs))


def check_dispatch(project, state, name, attrs, snapshots):
    args = stage(state)
    state.regs.ra,state.regs.pc = RETURN_PC,glyph.STAGED_DRAW
    for i,arg in enumerate(args[:4]):
        setattr(state.regs,f"a{i}",arg)
    state.memory.store(STACK_TOP+16,struct.pack("<3I",*args[4:]),inspect=False)
    previous = block_count(state)
    sim = project.factory.simgr(state,save_unconstrained=True)
    sim.explore(find=(glyph.RENDER,STRETCH),n=DISPATCH_CAP)
    assert len(sim.found) == 1 and not (sim.active or sim.errored or sim.deadended or sim.unconstrained)
    final = sim.found[0]
    return dict(name=name, attributes=attrs, context_snapshots=snapshots, renderer=hex(final.addr),
                return_address=hex(concrete(final,final.regs.ra)),
                renderer_args=arguments(final,7 if final.addr == glyph.RENDER else 9),
                vex_block_events=block_count(final)-previous, cap=DISPATCH_CAP)


def scaled_oracle(blob):
    """Predict this horizontal-only scale with truncated Q16 and half-step samples."""
    _,sources = glyph.packed_oracle(blob,UNITS)
    frame = bytearray([glyph.FILL])*(glyph.WIDTH*glyph.HEIGHT)
    x,y = glyph.CONTEXT["origin"]
    cell_width,cell_height = glyph.CONTEXT["font_cell"]
    row_bytes = glyph.CONTEXT["source_row_bytes"]
    factor = (48 << 16)//cell_width
    calls = []
    for source in sources:
        offset = int(source["raw_source_offset"],16)-glyph.FONT_OFFSET
        width,height = source["width"],source["height"]
        dest_width = (width*factor) >> 16
        assert height == cell_height == 48
        assert 0 <= x < x+dest_width <= glyph.WIDTH and 0 <= y < y+height <= glyph.HEIGHT
        step = (width << 16)//dest_width
        columns = [(col*step+(step >> 1)) >> 16 for col in range(dest_width)]
        for row in range(height):
            for col,source_col in enumerate(columns):
                packed = blob[offset+row*row_bytes+source_col//4]
                code = (packed >> (6-2*(source_col%4))) & 3
                if code:
                    frame[(y+row)*glyph.WIDTH+x+col] = glyph.CONTEXT["pixel_indices"][code]
        calls.append(dict(pc=hex(STRETCH),ra="0x8022c46c",
                          args=[glyph.CTX,glyph.FONT+offset,cell_width,x,y,width,height,dest_width,height]))
        x += dest_width
    return frame,calls


def check_scaled(project, angr, state, blob, attrs):
    observed = []

    def entered(st):
        observed.append(dict(pc=hex(STRETCH),ra=hex(concrete(st,st.regs.ra)),args=arguments(st,9)))

    state.inspect.b("instruction",when=angr.BP_BEFORE,instruction=STRETCH,action=entered)
    previous = block_count(state)
    final = execute(project,state,glyph.STAGED_DRAW,*stage(state),steps=SCALE_CAP)
    expected,calls = scaled_oracle(blob)
    actual = value(final,glyph.FRAME,glyph.WIDTH*glyph.HEIGHT)
    result = concrete(final,final.regs.v0)
    assert result == 1 and observed == calls and actual == expected
    assert value(final,glyph.FRAME-8,8) == value(final,glyph.FRAME+len(actual),8) == b"G"*8
    return dict(entry=hex(glyph.STAGED_DRAW), return_value=result, attributes=attrs, binding=BINDING,
                whole_frame_equal=True, frame_sha256=sha256(actual).hexdigest(),
                changed_bytes=sum(byte != glyph.FILL for byte in actual),
                indexed_histogram={str(i):n for i,n in sorted(Counter(actual).items())},
                renderer_calls=observed, vex_block_events=block_count(final)-previous, sim_explore_step_cap=SCALE_CAP)


def validate_report(report):
    """Validate replay observations with the Python standard library alone."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert report["input_sha256"] == SHA and report["analysis_elf_sha256"] == ELF_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["resource"] == glyph.RESOURCE and report["context_template"] == glyph.CONTEXT
    assert report["modeled_boundaries"] == MODELED
    assert report["units"] == list(UNITS) and report["refresh"] == expected_refresh()
    assert glyph.digest(report["loader_events"]) == glyph.LOADER_SHA256
    assert tuple(glyph.digest(row) for row in report["dispatch"]) == DISPATCH_SHA256
    assert glyph.digest(report["scaled"]) == SCALE_SHA256


def replay(firmware, elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    blob = glyph.read_font(firmware)
    import angr

    refresh = capture_refresh(load_project(elf),angr)
    attrs = [row["args"] for row in refresh["srgb_groups"][0][:3]]
    project = load_project(elf)
    initial,loader = glyph.prepare_font(project,angr,blob)
    assert glyph.digest(loader) == glyph.LOADER_SHA256
    configured,snapshots = apply_attributes(project,initial.copy(),attrs)
    dispatch = [check_dispatch(project,initial.copy(),"default-without-attributes",[],
                               [dict(after=None,fields=context_fields(initial))]),
                check_dispatch(project,configured.copy(),"captured-attributes-draw-id-17",attrs,snapshots)]
    assert tuple(glyph.digest(row) for row in dispatch) == DISPATCH_SHA256
    report = dict(input_sha256=SHA, analysis_elf_sha256=ELF_SHA256, engine=f"angr {angr.__version__} / VEX",
                  resource=glyph.RESOURCE, context_template=glyph.CONTEXT, modeled_boundaries=MODELED,
                  units=list(UNITS), loader_events=loader, refresh=refresh, dispatch=dispatch,
                  scaled=check_scaled(project,angr,configured,blob,attrs))
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware",type=Path)
    parser.add_argument("elf",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error("replay requires assertions")
    if lexists(args.output):
        parser.error("output must not exist")
    report = replay(args.firmware.read_bytes(),args.elf)
    with args.output.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(report,stream,indent=2)
        stream.write("\n")
    print("PASS 4 unchanged refreshes, 2 native dispatch controls, 1 scaled indexed frame")


if __name__ == "__main__":
    main()
