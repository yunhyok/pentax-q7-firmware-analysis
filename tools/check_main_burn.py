"""Replay two bounded Q7 MAIN Burn prefixes with guarded synthetic RAM."""
import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path

from check_burn_storage import arguments, num, put_u32, read_bytes, u32
from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project
from check_q7_portability import execute, guard, new_state
from q7_symbols import SHA


GET_HANDLE, BURN, BURN_NAND = 0x805E4FE4, 0x805E5374, 0x805DD7B8
CALLBACKS,CARD_READ,HOST_ACK=0x805E8854,0x805E1684,0x805E1A00
NAND_WRAPPER,NAND_EX,FILE_READ=0x80053E70,0x80053124,0x80071A10
HANDLE_GLOBAL,FILE_GLOBAL,MUTEX_GLOBAL=0x805E8864,0x815EDDD0,0x800631D0
HEADER, FILE, HANDLE = 0x24000000, 0x24001000, 0x24002000
MUTEX, MEDIA_INFO, OPEN_RAM = 0x24003000, 0x24004000, 0x24006000
PRIMARY,SECONDARY,TEMP,INSTALLED=0x24100000,0x24200000,0x24300000,0x24400000
CHUNK=0x20000
UPDATE_HEADER_OFFSET, INSTALLED_FIXTURE_OFFSET = 0x100000, 0x1000C0
UPDATE_HEADER_SIZE, INSTALLED_FIXTURE_SIZE = 0xC0, 0x600
HANDLE_STEP_LIMIT, STEP_LIMIT = 1000, 5000
NATIVE_OPEN_MODELS = {
    "0x8000c2b4": "Supply zeroed synthetic allocation for the handle, media-info state and FileX buffer.",
    "0x800cbee4": "Accept mutex get for the seeded synthetic mutex.",
    "0x800d193c": "Accept mutex put for the seeded synthetic mutex.",
    "0x800a14f8": "Record diagnostics without printing firmware text.",
}
INSTALLED_HEADER_MODELS = {
    **NATIVE_OPEN_MODELS,
    "0x8000bf28": "Supply synthetic primary, secondary, installed-header and card comparison buffers.",
    "0x80067700": "Set synthetic medium selector and return 0xf1 at installed-media FileX open.",
    "0x80069b94": "Supply installed-media geometry of 256 sectors per block and 262144 sectors.",
    "0x80053124": "After observing the first request, return op 6 with 16 FF spare bytes and op 4 with the 0x600-byte installed-header fixture.",
    "0x800b1edc": "Record card comparison-buffer cache invalidation without cache effects.",
}
REPLAY_SHA256 = "7d038adc5fd168e566bcb78079878bc91c3cc8e9547cb0bcb312b15f1676f2c1"


def replay_mode(p, angr, header, installed, *, native_open):
    events=[]

    class Model(angr.SimProcedure):
        def run(self,*,api):
            st=self.state
            args=arguments(st)
            a0, a1, a2, _ = args[:4]
            ra=num(st,st.regs.ra)
            row=dict(api=hex(api),return_address=hex(ra))
            result=0
            if api==0x8000C2B4:
                size=a1*a2
                result={0xD40:HANDLE,0xC90:MEDIA_INFO,0x2000:OPEN_RAM}[size]
                st.memory.store(result,bytes(size),size=size)
                row.update(size=size,address=hex(result))
            elif api==0x8000BF28:
                if a1==CHUNK+16:
                    result={0x805E54E4:PRIMARY,0x805E5504:SECONDARY}[ra]
                else:
                    result={0x600:INSTALLED,CHUNK:TEMP}[a1]
                st.memory.store(result,bytes(a1),size=a1)
                row.update(size=a1,address=hex(result))
            elif api in (0x800CBEE4,0x800D193C):
                assert a0==MUTEX
            elif api==0x80067700:
                assert args==[HANDLE,0x805EA90C,0x8006444C,0,OPEN_RAM,0x2000,0x80000000]
                put_u32(st,HANDLE+0xC24,0)
                result=0xF1
                row["arguments"]=[hex(arg) for arg in args]
            elif api==0x80069B94:
                assert a0==HANDLE and a1==HANDLE+0xC78
                put_u32(st,a1+0x10,256)
                put_u32(st,a1+0x14,1024*256)
                row["geometry"]=[256,1024*256]
            elif api==NAND_EX:
                sp=num(st,st.regs.sp)
                extra_size=u32(st,sp+28)
                dev,handle,operation,sector,count,data,extra=args
                assert (dev,handle,sector)==(1,HANDLE,0)
                if operation==6:
                    assert count==1 and data==0 and extra_size==16
                    st.memory.store(extra,b"\xff"*16,size=16)
                else:
                    assert operation==4 and (count,data,extra,extra_size)==(3,INSTALLED,0,0)
                    st.memory.store(data,installed,size=len(installed))
                    row["supplied_sha256"]=sha256(installed).hexdigest()
                row.update(operation=operation,sector=sector,count=count,data=hex(data),
                           extra=hex(extra),extra_size=extra_size)
            elif api==0x800B1EDC:
                assert (a0,a1)==(TEMP,CHUNK)
                row["arguments"]=[hex(a0),hex(a1)]
            else:
                assert api==0x800A14F8
            events.append(dict(row,result=result))
            return result

    models = NATIVE_OPEN_MODELS if native_open else INSTALLED_HEADER_MODELS
    for address in models:
        api = int(address,16)
        p.hook(api,Model(num_args=0,api=api))
    st=new_state(p,angr)
    st.memory.store(STACK_TOP-0x2000,bytes(0x2000),inspect=False)
    st.memory.store(HEADER,header,inspect=False)
    put_u32(st,HANDLE_GLOBAL,0)
    put_u32(st,FILE_GLOBAL,FILE)
    put_u32(st,MUTEX_GLOBAL,MUTEX)
    put_u32(st,MUTEX_GLOBAL+4,0)
    put_u32(st,MUTEX_GLOBAL+8,0)
    ram=[(STACK_TOP-0x2000,STACK_TOP-0x400),(HANDLE_GLOBAL,HANDLE_GLOBAL+4),
         (MUTEX_GLOBAL,MUTEX_GLOBAL+12),(HANDLE,HANDLE+0xD40),(MEDIA_INFO,MEDIA_INFO+0xC90),
         (OPEN_RAM,OPEN_RAM+0x2000),(PRIMARY,PRIMARY+CHUNK+16),(SECONDARY,SECONDARY+CHUNK+16),
         (TEMP,TEMP+CHUNK),(INSTALLED,INSTALLED+0x600)]
    if native_open:
        put_u32(st,0x81547F10,0)
        put_u32(st,0x8008C2F4,0)
        st.memory.store(0x8008C2DC,b"\0",inspect=False)
        ram.extend(((0x8008C2DC,0x8008C2DD),(0x8008C2F4,0x8008C2F8)))
    image=tuple((seg.min_addr,seg.max_addr+1) for seg in p.loader.main_object.segments)
    guard(st,angr,ram,(*image,(HEADER,HEADER+len(header)),(FILE_GLOBAL,FILE_GLOBAL+4),(0x81547F10,0x81547F14)))

    st=execute(p,st,GET_HANDLE,HEADER,steps=HANDLE_STEP_LIMIT)
    assert num(st,st.regs.v0)==HANDLE

    fields={hex(off):u32(st,HANDLE+off) for off in (0xCA4,0xCA8,0xCB4,0xCBC,0xCC0,0xCC4,0xCC8)}
    assert fields == {
        "0xca4": BURN_NAND, "0xca8": 0x8006444C, "0xcb4": 3, "0xcbc": 1,
        "0xcc0": 0, "0xcc4": 24, "0xcc8": 0,
    }
    before=len(list(st.history.bbl_addrs))
    st.regs.pc,st.regs.ra=BURN,RETURN_PC
    st.regs.a0,st.regs.a1,st.regs.a2=HANDLE,CHUNK,CALLBACKS
    sim=p.factory.simgr(st,save_unconstrained=True)

    def advance(sim,target):
        sim.explore(find=target,avoid=RETURN_PC,n=STEP_LIMIT)
        if len(sim.found)!=1 or sim.active or sim.errored or sim.unconstrained or sim.deadended or sim.avoid:
            raise RuntimeError((hex(target),sim,sim.errored,[hex(s.addr) for s in sim.active]))
        return sim.found.pop()

    first=advance(sim,NAND_EX)
    first_args=arguments(first)+[u32(first,num(first,first.regs.sp)+28)]
    if native_open:
        assert first_args==[1,HANDLE,2,0,0,STACK_TOP-0x48-0x30-0x70-0x28-0x268+0x20,0,16],first_args
        assert read_bytes(first,first_args[5],8)==b"\xff"*8
        assert num(first,first.regs.ra)==0x80053F0C
        history=list(first.history.bbl_addrs)[before:]
        for addr in (BURN,0x80055F20,0x800554C8,0x80067700,0x80066A5C,0x8006444C,
                     0x8006423C,0x8008389C,0x8007E630,NAND_WRAPPER):
            assert addr in history,hex(addr)
        assert not any(addr in history for addr in (BURN_NAND,HOST_ACK,CARD_READ,0x80056644))
        report=dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,handle_fields=fields,
                    entry=hex(BURN),stop_before=hex(NAND_EX),arguments=[hex(x) for x in first_args],
                    return_address=hex(num(first,first.regs.ra)),vex_blocks=len(history),events=events)
        assert set(models) == {row['api'] for row in events}
        return report
    assert first_args[:7]==[1,HANDLE,6,0,1,0,STACK_TOP-0x48-0x690-0x40-0x50+0x20],first_args
    assert first_args[7]==16 and num(first,first.regs.ra)==0x80053F0C
    assert not any(e.get("operation") is not None for e in events)
    history=list(first.history.bbl_addrs)[before:]
    for addr in (BURN,0x80055F20,0x800554C8,HOST_ACK,BURN_NAND,0x80056644,0x80055A3C,NAND_WRAPPER):
        assert addr in history,hex(addr)
    assert CARD_READ not in history
    first_count=len(history)

    assert not sim.active
    sim.stashes["active"]=[first]
    card=advance(sim,FILE_READ)
    operations=[e for e in events if "operation" in e]
    assert [(e["operation"],e["sector"],e["count"]) for e in operations]==[(6,0,1),(4,0,3)]
    assert u32(card,HANDLE+0xC98)==CHUNK and u32(card,HANDLE+0xC9C)==PRIMARY
    assert u32(card,HANDLE+0xCA0)==SECONDARY
    assert read_bytes(card,INSTALLED,len(installed))==installed
    card_args=arguments(card)[:4]
    assert card_args[:3]==[FILE,PRIMARY,CHUNK] and num(card,card.regs.ra)==0x805E1754
    assert CARD_READ in list(card.history.bbl_addrs)[before:]
    report=dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,
                handle_fields=fields,callback_words=[hex(u32(card,a)) for a in (CALLBACKS,CALLBACKS+4)],
                first_nand_ex=dict(arguments=[hex(x) for x in first_args],vex_blocks=first_count),
                first_card_filex=dict(arguments=[hex(x) for x in card_args],return_address="0x805e1754",
                                      intended_payload_offset="0x1000c0",vex_blocks=len(list(card.history.bbl_addrs)[before:])),
                events=events)
    assert set(models) == {row['api'] for row in events}
    return report


def replay(firmware, elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    if sha256(firmware).hexdigest() != SHA:
        raise ValueError("expected SHA-pinned Q7 v1.01")
    header = firmware[UPDATE_HEADER_OFFSET:UPDATE_HEADER_OFFSET+UPDATE_HEADER_SIZE]
    installed = firmware[INSTALLED_FIXTURE_OFFSET:INSTALLED_FIXTURE_OFFSET+INSTALLED_FIXTURE_SIZE]
    assert len(header) == UPDATE_HEADER_SIZE and len(installed) == INSTALLED_FIXTURE_SIZE
    import angr

    report = dict(
        input_sha256=SHA,
        analysis_elf_sha256=ELF_SHA256,
        engine=f"angr {angr.__version__} / VEX",
        modeled_apis=dict(native_open=NATIVE_OPEN_MODELS, installed_header=INSTALLED_HEADER_MODELS),
        fixture=dict(
            update_header=dict(original_file_offset=hex(UPDATE_HEADER_OFFSET), size=UPDATE_HEADER_SIZE,
                               sha256=sha256(header).hexdigest()),
            installed_header=dict(borrowed_package_offset=hex(INSTALLED_FIXTURE_OFFSET), size=INSTALLED_FIXTURE_SIZE,
                                  sha256=sha256(installed).hexdigest(), actual_installed_media=False),
            caps=dict(handle_init=HANDLE_STEP_LIMIT, per_prefix_phase=STEP_LIMIT),
        ),
        native_open=replay_mode(load_project(elf),angr,header,installed,native_open=True),
        installed_header=replay_mode(load_project(elf),angr,header,installed,native_open=False),
    )
    validate_report(report)
    return report


def digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii")).hexdigest()


def validate_report(report):
    """Validate both bounded traces without loading angr or firmware."""
    if not __debug__:
        raise RuntimeError("validation requires assertions")
    assert digest(report) == REPLAY_SHA256, "MAIN Burn prefix observations differ"


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
    with args.output.open("x",encoding="utf-8",newline="\n") as out:
        json.dump(report,out,indent=2)
        out.write("\n")
    print("PASS original MAIN native-open and installed-header prefix fixtures")


if __name__ == "__main__":
    main()
