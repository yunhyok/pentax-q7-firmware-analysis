"""Replay FC configure/export and FC1 setter/writer from pinned Q7 instructions."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256
from check_color_handoff import OBJECT, WRAPPER, PAYLOAD, RETURN, STACK

BLOCK, PASS_INPUT, MATRIX = 0x10004000,0x10005000,0x10006000
HDR = [612,1202,233,-346,-678,1024,1024,-857,-167,2048,2048]
SCOPE = "Original FC constructor/configure/export -> FC1 setter/writer; synthetic per-pass inputs and RAM MMIO. Full FIPLIB topology, scheduler, enable gate and camera pixels are not executed."


def fixtures():
    edge=[-32768,32767,-1,0,1,-257,8192,16384,-123,2048,-2048]
    preset709=[435,1465,148,-236,-792,1028,1028,-934,-94,2048,2048]
    unity=[2048,0,0,0,2048,0,0,0,2048,0,0]
    for name,mode,custom,field28,field29,field64,field65,values,flags in [
        ('hdr-custom-flag0',1,HDR,0,0,0,0,HDR,0),
        ('hdr-custom-flag1',1,HDR,1,0,0,0,HDR,1),
        ('signed-boundary-custom',1,edge,0xFE,0,1,0,edge,0),
        ('mode1-null-601',1,None,0,0,0,0,HDR,0),
        ('mode1-null-709',1,None,0,0,1,0,preset709,0),
        ('mode3-null-unity',3,None,0,2,0,3,unity,6)]:
        words=[v & 0xFFFFFFFF for v in values]+[flags]
        offsets=[*range(0xC0,0xEC,4),0xFC]
        yield dict(case=name,mode=mode,custom=custom,field28=field28,field29=field29,
                   field64=field64,field65=field65,expected_halfwords=values,expected_flags=flags,
                   expected_export_u32=words,expected_mmio=[[0xB6000000+off,4,v] for off,v in zip(offsets,words,strict=True)])


def reference():
    return dict(analysis_elf_sha256=ELF_SHA256,scope=SCOPE,
                functions=['0x8017a974','0x8017ab94','0x8017ad04','0x8031f64c','0x8031f750'],cases=list(fixtures()))


def replay(elf):
    if not __debug__: raise RuntimeError('Replay validation requires assertions; do not use python -O')
    if hashlib.sha256(elf.read_bytes()).hexdigest()!=ELF_SHA256: raise ValueError('expected SHA-pinned Q7 ELF')
    import angr
    project=angr.Project(str(elf),auto_load_libs=False)
    for case in fixtures():
        state=project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        state.regs.sp=STACK
        for address,size in [(BLOCK,0x40),(PASS_INPUT,0x80),(MATRIX,0x20),(WRAPPER,0x24),(PAYLOAD,0x5E0),(OBJECT,0x4C)]:
            state.memory.store(address,bytes(size))
        state.memory.store(OBJECT+0x29,b'\1')
        state.memory.store(WRAPPER+0x1C,struct.pack('<I',PAYLOAD))
        for offset in (0x28,0x29,0x64,0x65):
            state.memory.store(PASS_INPUT+offset,bytes([case[f'field{offset:x}']]))
        if case['custom'] is not None:
            state.memory.store(MATRIX,struct.pack('<11h',*case['custom']))
            state.memory.store(PASS_INPUT+(0x68 if case['mode']==1 else 0x6C),struct.pack('<I',MATRIX))
        events=[]
        def on_write(s):
            address=s.solver.eval(s.inspect.mem_write_address)
            if 0xB6000000<=address<0xB6001000:
                assert not s.inspect.mem_write_expr.symbolic
                events.append([address,s.solver.eval(s.inspect.mem_write_length),s.solver.eval(s.inspect.mem_write_expr)])
        state.inspect.b('mem_write',when=angr.BP_BEFORE,action=on_write)
        for address,a0,a1 in [(0x8017A974,BLOCK,case['mode']),(0x8017AB94,BLOCK,PASS_INPUT),
                              (0x8017AD04,BLOCK,PAYLOAD+0x100),(0x8031F64C,OBJECT,WRAPPER),
                              (0x8031F750,OBJECT,0)]:
            state.regs.pc,state.regs.ra=address,RETURN
            state.regs.a0,state.regs.a1=a0,a1
            sim=project.factory.simgr(state);sim.explore(find=RETURN,n=256)
            assert len(sim.found)==1 and not sim.active and not sim.errored,case['case']
            state=sim.found[0]
            assert state.solver.eval(state.regs.sp)==STACK
        for address,expected in [(BLOCK+0x10,struct.pack('<11h',*case['expected_halfwords'])),
                                 (PAYLOAD+0x100,struct.pack('<12I',*case['expected_export_u32'])),
                                 (OBJECT+0x30,struct.pack('<11h',*case['expected_halfwords'])),
                                 (OBJECT+0x48,struct.pack('<I',case['expected_flags']))]:
            actual=state.memory.load(address,len(expected))
            assert not actual.symbolic and state.solver.eval(actual,cast_to=bytes)==expected,case['case']
        assert events==case['expected_mmio'],case['case']
    return reference()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error('output must not exist')
    args.output.write_text(json.dumps(replay(args.elf),indent=2)+'\n',encoding='utf-8')
    print('6 FC generator/export/setter/writer cases; 72 ordered MMIO writes PASS')


if __name__=='__main__': main()
