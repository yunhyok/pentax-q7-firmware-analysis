"""Replay FC1 enable translation and active-low direct/CBC emission."""
import argparse
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256, load_project
from check_color_handoff import OBJECT, WRAPPER, PAYLOAD, RETURN, STACK

CHUNK, DATA = 0x10008000, 0x10009000
SCOPE = 'Original FC1 constructor, FIPLIB enable translator, inherited setter and direct/CBC enable writers; synthetic payload and RAM MMIO, no scheduler or hardware.'


def reference():
    return dict(analysis_elf_sha256=ELF_SHA256,scope=SCOPE,
        cases=[dict(payload_word=v,enabled=int((v&255)==0),
                    mmio=[0xB60000EC,4,int((v&255)!=0)],cbc=[0xB60000EC,int((v&255)!=0)])
               for v in (0,1,2,0x100,0x101,0xFFFFFFFF)])


def replay(elf):
    if not __debug__: raise RuntimeError('Replay validation requires assertions')
    import angr
    project=load_project(elf)
    for case in reference()['cases']:
        state=project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        state.regs.sp=STACK
        for address,size in ((OBJECT,0x4c),(WRAPPER,0x24),(PAYLOAD,0x5e0),(CHUNK,0x10),(DATA,0x20)):
            state.memory.store(address,bytes(size))
        def word(address,value): state.memory.store(address,struct.pack('<I',value))
        word(WRAPPER+0x1c,PAYLOAD);word(PAYLOAD+0x44,case['payload_word']);word(CHUNK,DATA)
        events=[]
        def on_write(s):
            address=s.solver.eval(s.inspect.mem_write_address)
            if 0xB6000000<=address<0xB6001000:
                assert not s.inspect.mem_write_expr.symbolic
                events.append([address,s.solver.eval(s.inspect.mem_write_length),s.solver.eval(s.inspect.mem_write_expr)])
        state.inspect.b('mem_write',when=angr.BP_BEFORE,action=on_write)
        for pc,args in [(0x8031F56C,[OBJECT,0]),(0x80349558,[0,OBJECT,WRAPPER,13]),
                        (0x80332680,[OBJECT]),(0x80332700,[OBJECT,CHUNK])]:
            state.regs.pc,state.regs.ra=pc,RETURN
            for i,v in enumerate(args): setattr(state.regs,f'a{i}',v)
            sim=project.factory.simgr(state);sim.explore(find=RETURN,n=256)
            assert len(sim.found)==1 and not sim.active and not sim.errored
            state=sim.found[0]
            assert state.solver.eval(state.regs.sp)==STACK
        assert events==[case['mmio']]
        for address,expected in [(OBJECT+0x28,bytes([case['enabled']])),
                                 (CHUNK+8,struct.pack('<I',2)),(DATA,struct.pack('<2I',*case['cbc']))]:
            value=state.memory.load(address,len(expected))
            assert not value.symbolic and state.solver.eval(value,cast_to=bytes)==expected
    return reference()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('elf',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists(): p.error('output must not exist')
    result=replay(args.elf)
    with args.output.open('x',encoding='utf-8') as out: out.write(json.dumps(result,indent=2)+'\n')
    print('6 FC1 enable cases: active-low MMIO and CBC pairs PASS')


if __name__=='__main__': main()
