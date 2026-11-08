"""Replay guarded Q7 OSD draw-context lookup before and after a native roll."""
import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct

from check_colorspace_render import CACHE, DRAW, FRAME, HEIGHT, PUBLISH, SHOW, STRIDE, set_screen
from check_colorspace_ui import concrete, get, put
from check_isp_registers import ELF_SHA256, load_project
from check_q7_portability import execute, guard, new_state, value
from q7_symbols import SHA


ACTIVE, REGISTRY, MAX_ID = 0x800EB4D8, 0x8029F340, 0x800EBD70
SET_PARAM, ROLL = 0x800EC08C, 0x8043CA4C
OSD_ATTR, TEXT, GDI_SIZE, GDI_TEXT = 0x8024BF9C,0x8024928C,0x802185D0,0x80229410
LOCK, UNLOCK, LOG = 0x800402CC,0x800404E8,0x800A14F8
TABLE, STAGED = 0x21020000,0x21030000
CONTEXT = {17:0x21000000,18:0x21010000}
FONT = {17:0x23000000,18:0x23010000}
SOURCE = b"\x01\x00"+struct.pack("<5H",84,51,40,35,0)
REPLAY_SHA256 = "d66c2c1527839f997363370400c672b96d10afed9985d9376ed8baf71fdff771"
SOURCE_SHA256 = "519b42c745c63aa09bb97f13e12ecc666a881ef4ce3dc2931d6e5b2c10da148c"


def replay_controls(p, angr):
    events = []

    def regs(st,count=4):
        return [concrete(st,getattr(st.regs,f"a{i}")) for i in range(count)]

    def call(st,pc,*args):
        return execute(p,st,pc,*args,steps=1000)

    class Model(angr.SimProcedure):
        def run(self,*,api):
            st=self.state
            a0, a1, a2, a3 = regs(st)
            if api==CACHE:
                assert (a0,a1)==(FRAME+0x100000*(get(st,DRAW,2)-17),STRIDE*HEIGHT)
                events.append(dict(kind="cache",address=hex(a0),size=a1))
            elif api==PUBLISH:
                assert (a0,a1,a2)==(0,get(st,SHOW,2),1)
                events.append(dict(kind="publish",layer=a0,id=a1,flag=a2))
                return 1
            elif api==GDI_SIZE:
                assert (a1,a2)==(48,48)
                events.append(dict(kind="attribute-setter",context=hex(a0),extent=[a1,a2]))
            elif api==GDI_TEXT:
                sp=concrete(st,st.regs.sp)
                assert (a2,a3)==(96,64)
                assert [get(st,sp+i) for i in (16,20,24,28)]==[0xFFFF,STAGED+2,1,4]
                assert value(st,STAGED+2,8)==SOURCE[2:10]
                events.append(dict(kind="text-render-entry",context=hex(a0),xy=[a2,a3],units=4))
            elif api==LOG:
                events.append(dict(kind="fallback-log"))
            else:
                assert api in (LOCK,UNLOCK)
            return 0

    for addr in (CACHE,PUBLISH,GDI_SIZE,GDI_TEXT,LOCK,UNLOCK,LOG):
        p.hook(addr,Model(num_args=0,api=addr))
    st=new_state(p,angr)
    set_screen(st)
    put(st,REGISTRY,TABLE)
    assert get(st,MAX_ID)==0x47
    st.memory.store(TABLE,bytes(0x124))
    put(st,TABLE,2)
    for i,ctx in CONTEXT.items():
        st.memory.store(ctx,bytes(0x40))
        put(st,ctx,FRAME+0x100000*(i-17))
        put(st,ctx+4,STRIDE,2)
        put(st,ctx+6,HEIGHT,2)
        put(st,ctx+0x18,FONT[i])
        put(st,TABLE+4+4*i,ctx)
    st.memory.store(STAGED,SOURCE)
    put(st,ACTIVE,0)
    image=tuple((s.min_addr,s.max_addr+1) for s in p.loader.main_object.segments)
    guard(st,angr,((0x80C6AE30,0x80C6AEB0),(ACTIVE,ACTIVE+4)),
          (*image,(TABLE,TABLE+0x124),(STAGED,STAGED+len(SOURCE)),
           *((ctx,ctx+0x40) for ctx in CONTEXT.values())))

    def watch_store(s):
        assert s.scratch.ins_addr==0x8024A610
        assert concrete(s,s.inspect.attrs.mem_write_length)==4
        events.append(dict(kind="native-active-store",source_store="0x8024a614",vex_pc=hex(s.scratch.ins_addr),
                           context=hex(concrete(s,s.inspect.attrs.mem_write_expr))))
    st.inspect.b("mem_write",when=angr.BP_BEFORE,mem_write_address=ACTIVE,action=watch_store)

    def draw_requests(st, expected):
        draw=get(st,DRAW,2)
        st = call(st, OSD_ATTR, draw, 7, 48, 48, 0, 0)
        assert concrete(st,st.regs.v0)==1
        st = call(st, TEXT, 0, 0xFFFF, STAGED, 96, 64, 4, 1)
        assert concrete(st,st.regs.v0)==1
        assert [e["context"] for e in events if e["kind"] in ("attribute-setter","text-render-entry")][-2:]==[hex(expected)]*2
        return st

    st=call(st,SET_PARAM,0x1BC,17)
    assert get(st,ACTIVE)==CONTEXT[17]
    assert events==[dict(kind="native-active-store",source_store="0x8024a614",vex_pc="0x8024a610",context=hex(CONTEXT[17]))]
    initial_store=events.pop()
    initial=st.copy()
    controls=[]
    for previous,next_id in [(17,18),(18,17)]:
        assert (get(st,DRAW,2),get(st,SHOW,2),get(st,ACTIVE))==(previous,next_id,CONTEXT[previous])
        st=draw_requests(st,CONTEXT[previous])
        st=call(st,ROLL)
        assert (get(st,DRAW,2),get(st,SHOW,2),get(st,ACTIVE))==(next_id,previous,CONTEXT[next_id])
        st=draw_requests(st,CONTEXT[next_id])
        assert [row["kind"] for row in events]==["attribute-setter","text-render-entry","cache","publish",
                                               "native-active-store","attribute-setter","text-render-entry"]
        controls.append(dict(draw_before=previous,draw_after=next_id,events=events.copy()))
        events.clear()

    # A missing next registry slot lets Screen IDs roll but blocks the native active-context store.
    initial.memory.store(TABLE+4+4*18,bytes(4),inspect=False)
    missing=call(initial,ROLL)
    assert get(missing,DRAW,2)==18 and get(missing,ACTIVE)==CONTEXT[17]
    missing=draw_requests(missing,CONTEXT[17])
    assert [row["kind"] for row in events]==["cache","publish","fallback-log","attribute-setter","text-render-entry"]
    report=dict(analysis_elf_sha256=ELF_SHA256,
                seed=dict(registry=hex(TABLE),contexts={str(i):hex(x) for i,x in CONTEXT.items()},
                          initial_draw=17,initial_show=18,max_id=0x47),
                initial_binding=initial_store, valid_rolls=controls,
                missing_slot=dict(draw_after=18,active_after=hex(CONTEXT[17]),events=events),
                step_cap_per_call=1000,
                models={hex(CACHE):"observe cache request",hex(PUBLISH):"record show request before hardware path",
                        hex(GDI_SIZE):"observe context before setter body",hex(GDI_TEXT):"observe context before glyph path",
                        hex(LOCK):"accept display resource lock",hex(UNLOCK):"accept display resource unlock",
                        hex(LOG):"observe missing-slot diagnostic"})
    return report


def digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()


def validate_report(report):
    """Check deterministic replay metadata without loading angr or firmware."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert digest(report) == REPLAY_SHA256, "Q7 context-binding observations differ"


def replay(firmware, elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    import angr

    controls = replay_controls(load_project(elf),angr)
    report = dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,
                  engine=f"angr {angr.__version__} / VEX",replay=controls)
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
    result = replay(args.firmware.read_bytes(),args.elf)
    with args.output.open("x",encoding="utf-8",newline="\n") as out:
        json.dump(result,out,indent=2)
        out.write("\n")
    print("PASS two original context rolls and one missing-slot control")


if __name__ == "__main__":
    main()
