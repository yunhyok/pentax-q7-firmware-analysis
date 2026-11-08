"""Replay a rebuilt function and Q7's actual burn-header dispatch offline."""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from check_isp_registers import ELF_SHA256
from inspect_q7 import parse_elf
from q7_symbols import SHA

RETURN,STACK,HEADER,HANDLE=0x0BADF000,0x70008000,0x10000000,0x10001000
PATCH_VA=0x803F0210


def replay(firmware,baseline,modified):
    if not __debug__: raise RuntimeError('Replay requires assertions')
    if hashlib.sha256(firmware).hexdigest()!=SHA or hashlib.sha256(baseline).hexdigest()!=ELF_SHA256:
        raise ValueError('expected pinned original Q7 firmware and analysis ELF')
    info,_=parse_elf(baseline,0)
    segment=next(s for s in info['segments'] if s['virtual_address']<=PATCH_VA<s['virtual_address']+s['file_size'])
    off=segment['file_offset']+PATCH_VA-segment['virtual_address']
    expected=bytearray(baseline)
    if expected[off:off+4]!=bytes.fromhex('21100000'): raise ValueError('unexpected original instruction')
    expected[off:off+4]=bytes.fromhex('01000224')
    if modified!=expected: raise ValueError('modified ELF differs outside the declared instruction')
    import angr
    def concrete(st,x):
        assert not x.symbolic
        return st.solver.eval(x)
    def run(project,pc,args=(),memory=()):
        st=project.factory.blank_state(addr=pc,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        st.regs.ra=RETURN;st.regs.sp=STACK;st.memory.store(STACK-0x1000,bytes(0x2000))
        for i,v in enumerate(args): setattr(st.regs,f'a{i}',v)
        for address,data in memory: st.memory.store(address,data)
        sim=project.factory.simgr(st);sim.explore(find=RETURN,n=2048)
        assert len(sim.found)==1 and not sim.active and not sim.errored,sim
        return sim.found[0]
    returns=[]
    for data in (baseline,modified):
        project=angr.Project(io.BytesIO(data),auto_load_libs=False)
        st=run(project,0x803F020C)
        returns.append(concrete(st,st.regs.v0))
    assert returns==[0,1]
    boot,syms=parse_elf(firmware,0x200)
    boot_bytes=firmware[0x200:boot['referenced_end']]
    project=angr.Project(io.BytesIO(boot_bytes),auto_load_libs=False)
    class Allocate(angr.SimProcedure):
        def run(self):
            self.state.memory.store(HANDLE,bytes(0x12F0));return HANDLE
    class Noop(angr.SimProcedure):
        def run(self): return 0
    project.hook(0x80034AAC,Allocate());project.hook(0x8004717C,Noop())
    burn_header=firmware[0x100000:0x1000C0]
    actual_kind=struct.unpack_from('<I',burn_header,8)[0]
    assert actual_kind==3 and struct.unpack_from('<H',burn_header,0x3C)[0]==0
    cases=[]
    for kind,hash_flag,target in ((3,0,0x80012654),(3,1,0x80012654),(8,0,0x8001E328),(5,0,0x80010F18),(7,0,None)):
        header=bytearray(burn_header)
        struct.pack_into('<I',header,8,kind);struct.pack_into('<H',header,0x3C,hash_flag)
        st=run(project,0x8001B134,[HEADER],[(HEADER,header),(0x800A7770,bytes(4))])
        result=concrete(st,st.regs.v0)
        assert result==(HANDLE if target else 0)
        if target:
            callback=concrete(st,st.memory.load(HANDLE+0x1254,4,endness='Iend_LE'))
            flag=concrete(st,st.memory.load(HANDLE+0x1278,1))
            assert (callback,flag)==(target,hash_flag)
        cases.append(dict(kind=kind,header_hash_flag=hash_flag,accepted_handle=bool(result),burn_callback=hex(target) if target else None))
    return dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,
                modified_elf_sha256=hashlib.sha256(modified).hexdigest(),patch_va=hex(PATCH_VA),
                baseline_return=returns[0],modified_return=returns[1],
                boot_elf_sha256=hashlib.sha256(boot_bytes).hexdigest(),burn_header_offset='0x100000',
                burn_header_size=192,burn_header_sha256=hashlib.sha256(burn_header).hexdigest(),
                actual_header_kind=actual_kind,actual_header_hash_flag=0,header_cases=cases,
                modeled_boot_functions={'0x80034aac':'allocator returns zeroed object','0x8004717c':'diagnostic output'},
                limits=['Rebuilt function is a controlled metadata-return experiment, not an AF/UI feature patch.',
                        'BurnGetHandle replay stops before any flash callback, queue or hardware operation.',
                        'The supplied header selects BurnNand with its optional MD5-worker flag zero; this does not rule out later checks.',
                        'No camera updater, boot, capture or recovery was exercised.'])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('firmware',type=Path);p.add_argument('baseline_elf',type=Path);p.add_argument('modified_elf',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists(): p.error('output must not exist')
    result=replay(a.firmware.read_bytes(),a.baseline_elf.read_bytes(),a.modified_elf.read_bytes())
    with a.output.open('x',encoding='utf-8') as f: f.write(json.dumps(result,indent=2)+'\n')
    print('Rebuilt return 0 to 1 and five burn-header dispatch cases PASS')


if __name__=='__main__': main()
