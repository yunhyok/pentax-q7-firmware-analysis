"""Load the pinned Q7 Latin font through original code and check indexed glyph rasterization."""
import argparse
from collections import Counter
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct

from check_colorspace_raster import CTX, FILL, FRAME, HEIGHT, MODELED as RASTER_MODEL, TABLE, WIDTH, prepare
from check_colorspace_ui import concrete, get, put
from check_isp_registers import ELF_SHA256, STACK_TOP, load_project
from check_q7_portability import execute, guard, value
from q7_symbols import SHA, read_file, root_files


FONT, TEXT, PATH, FILE, MEDIA = 0x23000000, 0x23100000, 0x23101000, 0x23200000, 0x23300000
LOAD, SELECT, DRAW, RENDER = 0x802612C0, 0x802183AC, 0x8022C058, 0x8022607C
STAGED_DRAW, STAGED_TRANSFER = 0x8024928C, 0x8022968C
STATIC_SIZE, STATIC_POINTER = 0x80234B04, 0x815D8578
FONT_PATH = r"A:\FontData\LatinFont.bin"
ROOT_RECORD, FONT_RECORD, FONT_OFFSET = 0x78D800, 0x7A05A0, 0x9D1AC0
FONT_SIZE = 130886
FONT_SHA256 = "9ba8e0f0b4fe85a9c097f7cd3e992ca6a159eef76ddc2340c2b6f6d22c1cc44b"
RESOURCE = {
    "directory_name": "FONTDATA",
    "directory_root_record": hex(ROOT_RECORD),
    "directory_first_cluster": 62,
    "directory_first_cluster_offset": "0x7a02c0",
    "directory_record": hex(FONT_RECORD),
    "short_name": "LATINF~6.BIN",
    "long_name": "LATINFONT.BIN",
    "long_name_record": hex(FONT_RECORD-32),
    "first_cluster": 2308,
    "declared_size": FONT_SIZE,
    "file_spans": [{"offset": FONT_OFFSET, "size": FONT_SIZE}],
    "sha256": FONT_SHA256,
}
CASES = (((84,), 37000, False), ((84, 51, 40, 35), 125000, True))
LOADER_SHA256 = "e2ea46220f9f0901535fe1b6f849ca3384779a8cbb529300e81ac724a606eab6"
CASE_SHA256 = (
    "d8938c3dd4aa92426a1b8b7b91553f1a49717b6e360e194bb16c175fe9731cc3",
    "89dfcff542216e0da5e5e7518c43cff2c91254397ce3537b44dc3064e7d398b1",
)
CONTEXT = dict(stride=WIDTH, height=HEIGHT, initial_index=FILL, origin=[96,64],
               font_cell=[64,48], source_bits_per_pixel=2, source_row_bytes=16,
               orientation=0, spacing_control=1, pixel_indices=[None,2,1,3])
LOADER_APIS = {
    0x80240E2C: "media",
    0x8007D180: "stat",
    0x8000BF28: "allocate",
    0x80074334: "open",
    0x80071A10: "read",
    0x8007C258: "close",
    0x8000C598: "free",
    0x800A14F8: "log",
}
MODELED = {
    "raster_setup": RASTER_MODEL,
    "font_load_and_draw": {
        "0x80240e2c": "Return a synthetic media pointer for the observed drive selector.",
        "0x8007d180": "Supply the verified FAT file size at the stat boundary.",
        "0x8000bf28": "After raster setup, allocate the synthetic FileX control block or font buffer.",
        "0x80074334": "Accept the normalized font path at FileX open.",
        "0x80071a10": "Supply the full verified font bytes and return success at FileX read.",
        "0x8007c258": "Accept FileX close for the modeled file.",
        "0x8000c598": "Record release of the FileX control block without allocator effects.",
        "0x800a14f8": "Record a diagnostic call without emitting text.",
    },
}


def read_font(firmware):
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    geometry, _, fat = root_files(firmware)
    root = firmware[ROOT_RECORD:ROOT_RECORD+32]
    assert root[:11] == b"FONTDATA   " and root[11] & 0x10
    directory_cluster, = struct.unpack_from("<H",root,26)
    assert directory_cluster == RESOURCE["directory_first_cluster"]
    directory = geometry["data_start"]+(directory_cluster-2)*geometry["cluster_size"]
    assert hex(directory) == RESOURCE["directory_first_cluster_offset"]
    assert directory <= FONT_RECORD < FONT_RECORD+32 <= directory+geometry["cluster_size"]
    record = firmware[FONT_RECORD:FONT_RECORD+32]
    assert record[:11] == b"LATINF~6BIN" and not record[11] & 0x18
    long_record = firmware[FONT_RECORD-32:FONT_RECORD]
    checksum = 0
    for byte in record[:11]:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xFF
    assert (long_record[0],long_record[11],long_record[13]) == (0x41,0x0F,checksum)
    long_name = (long_record[1:11]+long_record[14:26]+long_record[28:32]).decode("utf-16le")
    assert long_name == RESOURCE["long_name"] == FONT_PATH.rsplit("\\",1)[1].upper()
    first, length = struct.unpack_from("<HI",record,26)
    assert (first,length) == (RESOURCE["first_cluster"],FONT_SIZE)
    blob, spans = read_file(firmware,geometry,fat,dict(name=RESOURCE["short_name"],first_cluster=first,size=length))
    assert spans == RESOURCE["file_spans"] and sha256(blob).hexdigest() == FONT_SHA256
    return blob


def packed_oracle(blob, units):
    assert blob[:10] == b"LatinFont\0" and struct.unpack_from("<I",blob,0x20)[0] == 0x202
    cell_width, cell_height = (struct.unpack_from("<I",blob,i)[0] for i in (0x24,0x2C))
    bits = blob[0x37]
    assert (cell_width,cell_height,bits) == (64,48,2)
    ranges, widths, bitmaps = (struct.unpack_from("<I",blob,i)[0] for i in (0x40,0x44,0x4C))
    assert struct.unpack_from("<I",blob,ranges+0x14)[0] == 1
    descriptor = ranges+0x18
    first_word, first_width = struct.unpack_from("<II",blob,descriptor+0x14)
    lower, upper = struct.unpack_from("<II",blob,descriptor+0x20)
    assert (lower,upper) == (0,0xAA)
    row_bytes = ((cell_width*bits+15)//16)*2
    assert row_bytes == CONTEXT["source_row_bytes"]
    pixels = bytearray([FILL])*(WIDTH*HEIGHT)
    glyphs = []
    x,y = CONTEXT["origin"]
    for unit in units:
        assert lower <= unit <= upper
        index = unit-lower
        width = blob[widths+first_width+index]
        source = bitmaps+2*first_word+index*row_bytes*cell_height
        assert source+row_bytes*cell_height <= len(blob)
        assert 0 <= x < x+width <= WIDTH and 0 <= y < y+cell_height <= HEIGHT
        count = 0
        for row in range(cell_height):
            for col in range(width):
                packed = blob[source+row*row_bytes+col//4]
                code = (packed >> (6-2*(col%4))) & 3
                if code:
                    pixels[(y+row)*WIDTH+x+col] = CONTEXT["pixel_indices"][code]
                    count += 1
        glyphs.append(dict(unit=unit,width=width,height=cell_height,x=x,y=y,
                           raw_source_offset=hex(FONT_OFFSET+source),changed_bytes=count))
        x += width
    return pixels,glyphs


def prepare_font(project, angr, blob):
    state = prepare(project,angr)
    state.register_plugin("inspect",state.inspect.__class__())
    state.memory.store(STACK_TOP-0x1000,bytes(0x1040),inspect=False)
    path_bytes = FONT_PATH.encode("ascii")+b"\0"
    state.memory.store(PATH,path_bytes)
    put(state,STATIC_SIZE,0)
    put(state,STATIC_POINTER,0)
    events = []

    def path_at(st, address):
        for size in range(1,256):
            if value(st,address+size-1,1) == b"\0":
                return value(st,address,size-1).decode("ascii")
        raise ValueError("unterminated font path")

    class Loader(angr.SimProcedure):
        def run(self, *, api):
            st = self.state
            a0,a1,a2,a3 = (concrete(st,getattr(st.regs,f"a{i}")) for i in range(4))
            kind = LOADER_APIS[api]
            result = 0
            event = dict(api=hex(api),kind=kind,return_address=hex(concrete(st,st.regs.ra)))
            if kind == "media":
                assert a0 == 2
                result = MEDIA
                event["selector"] = a0
            elif kind == "stat":
                assert a0 == MEDIA
                event["path"] = path_at(st,a1)
                st.memory.store(a2+8,struct.pack("<I",len(blob)),size=4)
                event["size"] = len(blob)
            elif kind == "allocate":
                assert a0 == a2 == 0 and a1 in (0x1F8,len(blob))
                result = FILE if a1 == 0x1F8 else FONT
                st.memory.store(result,bytes(a1),size=a1)
                event["size"] = a1
            elif kind == "open":
                assert (a0,a1,a3) == (MEDIA,FILE,0)
                event["path"] = path_at(st,a2)
            elif kind == "read":
                assert (a0,a1,a2,a3) == (FILE,FONT,len(blob),0)
                st.memory.store(FONT,blob,size=len(blob))
                event["size"] = a2
            elif kind == "close":
                assert a0 == FILE
            elif kind == "free":
                assert a1 == FILE
            if kind in ("stat","open"):
                assert event["path"] == FONT_PATH[2:]
            events.append(dict(event,result=result))
            return result

    for api in LOADER_APIS:
        project.hook(api,Loader(num_args=0,api=api),replace=True)
    ram = ((STACK_TOP-0x1000,STACK_TOP-0x400),(CTX,CTX+0x8B0),
           (CTX+0x1000,CTX+0x100C),(FRAME,FRAME+WIDTH*HEIGHT))
    image = tuple((seg.min_addr,seg.max_addr+1) for seg in project.loader.main_object.segments)
    globals_ram = ((STATIC_SIZE,STATIC_SIZE+4),(STATIC_POINTER,STATIC_POINTER+4))
    guard(state,angr,(*ram,(FONT,FONT+len(blob)),(FILE,FILE+0x1F8),*globals_ram),
          (*image,(PATH,PATH+len(path_bytes))))
    state = execute(project,state,LOAD,PATH,0,steps=8000)
    assert concrete(state,state.regs.v0) == FONT
    assert get(state,STATIC_SIZE) == 0
    assert get(state,FONT+0x50) == 0x80236538
    state = execute(project,state,SELECT,CTX,FONT)
    assert get(state,CTX+0x18) == FONT
    assert get(state,CTX+0x82C,2) == 64 and get(state,CTX+0x82E,2) == 48
    assert get(state,CTX+0x88C) == RENDER
    assert [get(state,CTX+i,1) for i in (0x830,0x831,0x83C,0x84C,0x84D)] == [0,1,1,0,0]
    assert [get(state,CTX+i) for i in (0x824,0x868)] == [0,0]
    assert [get(state,CTX+i) for i in (0x24,0x28,0x2C,0x30)] == [0,2,1,3]
    state.register_plugin("inspect",state.inspect.__class__())
    guard(state,angr,ram,(*image,(FONT,FONT+len(blob)),(TEXT,TEXT+12),(TABLE,TABLE+0x100),
                          (0x800EB4D8,0x800EB4DC),(0x800EBD70,0x800EBD74),(0x8029F340,0x8029F344)))
    return state,events


def render_case(project, angr, initial, blob, units, cap, staged):
    state = initial.copy()
    text = struct.pack("<"+"H"*len(units),*units)
    source = b"\x01\x00"+text+b"\0\0" if staged else text
    state.memory.store(TEXT,source,inspect=False)
    observed, draw_calls = [], []

    def observe_draw(st):
        registers = [concrete(st,getattr(st.regs,f"a{i}")) for i in range(4)]
        sp = concrete(st,st.regs.sp)
        pointer,count = (get(st,sp+i) for i in (16,20))
        assert registers == [FONT,CTX,*CONTEXT["origin"]] and count == len(units)
        assert pointer == (0x70000D72 if staged else TEXT)
        assert value(st,pointer,len(text)) == text
        draw_calls.append(dict(pc=hex(DRAW),return_address=hex(concrete(st,st.regs.ra)),
                               arguments=[hex(item) for item in (*registers,pointer,count)],
                               text_sha256=sha256(text).hexdigest()))

    def observe(st):
        ctx, source, cell_width, x = (concrete(st,getattr(st.regs,f"a{i}")) for i in range(4))
        sp = concrete(st,st.regs.sp)
        assert ctx == CTX and cell_width == 64
        y, width, height = (get(st,sp+i) for i in (16,20,24))
        observed.append(dict(pc=hex(RENDER),return_address=hex(concrete(st,st.regs.ra)),
                             x=x,y=y,width=width,height=height,
                             raw_source_offset=hex(FONT_OFFSET+source-FONT)))

    state.inspect.b("instruction",when=angr.BP_BEFORE,instruction=DRAW,action=observe_draw)
    state.inspect.b("instruction",when=angr.BP_BEFORE,instruction=RENDER,action=observe)
    if staged:
        args = (0,0xFFFF,TEXT,*CONTEXT["origin"],len(units),1)
        final = execute(project,state,STAGED_DRAW,*args,steps=cap)
    else:
        args = (FONT,CTX,*CONTEXT["origin"],TEXT,len(units))
        final = execute(project,state,DRAW,*args,steps=cap)
    assert len(draw_calls) == 1
    if staged:
        assert draw_calls[0]["return_address"] == hex(STAGED_TRANSFER+8)
    actual = value(final,FRAME,WIDTH*HEIGHT)
    expected,glyphs = packed_oracle(blob,units)
    assert actual == expected
    assert value(final,FRAME-8,8) == value(final,FRAME+WIDTH*HEIGHT,8) == b"G"*8
    for hit,glyph in zip(observed,glyphs,strict=True):
        assert hit == dict(pc=hex(RENDER),return_address="0x8022c2b0",
                           **{key:glyph[key] for key in ("x","y","width","height","raw_source_offset")})
    history = list(final.history.bbl_addrs)[len(list(initial.history.bbl_addrs)):]
    assert history.count(RENDER) == len(units)
    return dict(units=list(units),entry=hex(STAGED_DRAW if staged else DRAW),
                vex_block_events=len(history),sim_explore_step_cap=cap,
                text_draw_call=draw_calls[0],renderer_calls=observed,frame_sha256=sha256(actual).hexdigest(),
                changed_bytes=sum(byte!=FILL for byte in actual),
                indexed_histogram={str(key):count for key,count in sorted(Counter(actual).items())},
                glyphs=glyphs)


def digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()


def validate_report(report):
    """Validate the deterministic observation without loading firmware or angr."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert report["input_sha256"] == SHA and report["analysis_elf_sha256"] == ELF_SHA256
    assert report["engine"].startswith("angr ") and report["engine"].endswith(" / VEX")
    assert report["resource"] == RESOURCE and report["context"] == CONTEXT
    assert report["modeled_boundaries"] == MODELED and report["loader_path"] == FONT_PATH
    assert digest(report["loader_events"]) == LOADER_SHA256
    assert tuple(digest(row) for row in report["cases"]) == CASE_SHA256


def replay(firmware, elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    blob = read_font(firmware)
    import angr

    project = load_project(elf)
    initial,events = prepare_font(project,angr,blob)
    report = dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,engine=f"angr {angr.__version__} / VEX",
                  resource=RESOURCE,context=CONTEXT,modeled_boundaries=MODELED,loader_path=FONT_PATH,
                  loader_events=events,cases=[render_case(project,angr,initial,blob,*case) for case in CASES])
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
    print(f"PASS {len(report['cases'])} LatinFont indexed raster fixtures")


if __name__ == "__main__":
    main()
