"""Replay Q7's application update-file gate with modeled file/allocator APIs."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from check_isp_registers import ELF_SHA256

ENTRY=0x807F1820
RETURN,STACK,BUFFER=0x0BADF000,0x70008000,0x10000000


def fixtures():
    body=bytes(range(64))
    footer=b'ORION\0\0\0KB538\0\0\x0077690\0\0\0'+struct.pack('<I',sum(body))+bytes((1,1,23,10))
    base=body+footer
    cases=[('valid',base,{},1)]
    for i,name in ((0,'code_name'),(8,'kb_number'),(16,'product_number'),(24,'checksum')):
        changed=bytearray(base);changed[-32+i]^=1
        cases.append(('wrong_'+name,bytes(changed),{},0))
    changed=bytearray(base);changed[-4:]=b'\xff'*4
    cases.append(('version_bytes_changed',bytes(changed),{},1))
    changed=bytearray(base);changed[0]=255
    cases.append(('changed_body_unrepaired',bytes(changed),{},0))
    struct.pack_into('<I',changed,len(changed)-8,sum(changed[:-32]))
    cases.append(('changed_body_repaired',bytes(changed),{},1))
    for name,override in (('empty_size',{'size':0}),('open_failure',{'open':0}),
                          ('short_footer',{'short_footer':1}),('allocation_failure',{'alloc':0}),
                          ('short_body',{'short_body':1})):
        cases.append((name,base,override,0))
    return cases


def reference():
    return dict(analysis_elf_sha256=ELF_SHA256,
        cases=[dict(name=name,input_size=len(data),input_sha256=hashlib.sha256(data).hexdigest(),
                    modeled_outcomes=override,expected_return=expected) for name,data,override,expected in fixtures()],
        modeled_functions={'0x80260e1c':'file size','0x8025fc7c':'file open','0x8025fdec':'relative seek',
                           '0x8025fd60':'file read','0x8025fc84':'file close','0x800ee804':'allocation',
                           '0x800ee86c':'free','0x800a14f8':'diagnostic output'},
        native_functions=['UpdateFW_IsCorrectUpdateFirmware','GetCodeName','GetKBNumber','GetProductNumber',
                          'strcmp','strcpy','byte-sum loop'],
        limits=['Synthetic 96-byte files exercise the original gate and checksum loop; no checksum-loop stub.',
                'Real package byte sums are checked separately in repack_q7.',
                'Application file gate only: no flash service, bootloader, hardware decoder, boot or shooting.'])


def replay(elf):
    if not __debug__: raise RuntimeError('Replay requires assertions')
    if hashlib.sha256(elf.read_bytes()).hexdigest()!=ELF_SHA256:
        raise ValueError('expected pinned original Q7 analysis ELF')
    import angr
    project=angr.Project(str(elf),auto_load_libs=False)
    def value(state,x):
        assert not x.symbolic
        return state.solver.eval(x)
    class Model(angr.SimProcedure):
        def run(self,a0,a1,a2,a3,*,kind):
            st=self.state;data=st.globals['file'];opts=st.globals['opts']
            if kind=='size':
                st.memory.store(value(st,a1),struct.pack('<Q',opts.get('size',len(data))))
            elif kind=='open': return opts.get('open',1)
            elif kind=='seek':
                offset=value(st,a2)
                whence=value(st,st.memory.load(value(st,st.regs.sp)+16,4,endness='Iend_LE'))
                assert (offset,whence) in ((32,1),(0,0))
                st.globals['position']=len(data)-32 if whence==1 else 0
            elif kind=='read':
                count=value(st,a2);position=st.globals['position']
                result=data[position:position+count]
                if (count==32 and opts.get('short_footer')) or (count==len(data) and opts.get('short_body')):
                    result=result[:-1]
                st.memory.store(value(st,a1),result)
                st.globals['position']=position+len(result)
                return len(result)
            elif kind=='alloc': return BUFFER if opts.get('alloc',1) else 0
            return 0
    mapping={0x80260E1C:'size',0x8025FC7C:'open',0x8025FDEC:'seek',0x8025FD60:'read',
             0x8025FC84:'close',0x800EE804:'alloc',0x800EE86C:'free',0x800A14F8:'log'}
    for address,kind in mapping.items(): project.hook(address,Model(kind=kind))
    for name,data,opts,expected in fixtures():
        state=project.factory.blank_state(addr=ENTRY,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        state.regs.sp=STACK;state.regs.ra=RETURN
        state.memory.store(STACK-0x1000,bytes(0x2000));state.memory.store(BUFFER,bytes(0x1000))
        state.memory.store(0x807F268C,b'F:\\fwdc603p.bin\0')
        state.globals['file']=data;state.globals['opts']=opts;state.globals['position']=0
        sim=project.factory.simgr(state);sim.explore(find=RETURN,n=4096)
        assert len(sim.found)==1 and not sim.errored and not sim.active,(name,sim)
        result=value(sim.found[0],sim.found[0].regs.v0)
        assert result==expected,(name,result,expected)
    return reference()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('elf',type=Path)
    p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    if args.output.exists(): p.error('output must not exist')
    report=replay(args.elf)
    with args.output.open('x',encoding='utf-8') as f: f.write(json.dumps(report,indent=2)+'\n')
    print(f'{len(report["cases"])} original update-gate cases PASS')


if __name__=='__main__': main()
