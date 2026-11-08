"""Replay two FIPLIB setters and register writers; synthetic inputs, no ISP pixels."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256

OBJECT, WRAPPER, PAYLOAD = 0x10001000, 0x10002000, 0x10003000
RETURN, STACK = 0x0BADF000, 0x70001000
SCOPE = "Direct FIPLIB setter then register writer with dirty=1 and synthetic RAM MMIO; dispatch gates, pass scheduling and pixels are not executed."


def fixtures():
    initial = [-32768, -123, -1, 0, 1, 73, 8192, 16384, 32767]
    supplied = [0x12348000, 0x7FFF, 0xFFFFFFFF, 0x00010000, 0xABCD0001,
                0xFFFF1234, 0x8000FFFF, 0x7FFF8001, 0x00012345, 0xFEDC, 0x8001, 0xDEADBEEF]
    companion = [0x11223344, 0x80000000, 0xFEDCBA98]
    for name, setter, writer, size in [('cm',0x803531BC,0x803537A4,0xC8),
                                      ('fc1',0x8031F64C,0x8031F750,0x4C)]:
        obj = bytearray([0xA5]*size)
        obj[0x29] = 1
        payload = bytearray(0x130)
        if name == 'cm':
            struct.pack_into('<9iH',obj,0x88,*initial,0xFEDC)
            struct.pack_into('<6I',obj,0xB0,11,22,33,44,55,66)
            struct.pack_into('<3I',payload,0xD0,*companion)
            expected = bytearray(obj)
            struct.pack_into('<3I',expected,0xB0,*companion)
            coeff = initial
            values = [*initial,0xFEDC,*companion,44,55,66]
            offsets = [*range(0x200,0x228,4),*range(0x1A8,0x1C0,4)]
        else:
            struct.pack_into('<11h',obj,0x30,*initial,-7,77)
            struct.pack_into('<I',obj,0x48,0x12345678)
            struct.pack_into('<12I',payload,0x100,*supplied)
            expected = bytearray(obj)
            signed = [((v & 0xFFFF)^0x8000)-0x8000 for v in supplied[:11]]
            struct.pack_into('<11h',expected,0x30,*signed)
            struct.pack_into('<I',expected,0x48,supplied[11])
            coeff, values = signed[:9], [*signed,supplied[11]]
            offsets = [*range(0xC0,0xEC,4),0xFC]
        writes = [[0xB6000000+off,4,value & 0xFFFFFFFF] for off,value in zip(offsets,values,strict=True)]
        result = dict(case=name,setter=hex(setter),writer=hex(writer),initial_coefficients=initial,
                      resulting_coefficients=coeff,coefficients_preserved=(coeff==initial),
                      object_sha256=hashlib.sha256(expected).hexdigest(),mmio_writes=writes)
        yield setter,writer,bytes(obj),bytes(payload),bytes(expected),result


def reference():
    return dict(analysis_elf_sha256=ELF_SHA256,scope=SCOPE,cases=[c[-1] for c in fixtures()])


def replay(elf):
    if not __debug__:
        raise RuntimeError('Replay validation requires assertions; do not use python -O')
    if hashlib.sha256(elf.read_bytes()).hexdigest() != ELF_SHA256:
        raise ValueError('expected SHA-pinned Q7 analysis ELF')
    import angr
    project = angr.Project(str(elf),auto_load_libs=False)
    for setter,writer,obj,payload,expected,result in fixtures():
        state = project.factory.blank_state(addr=setter,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        state.regs.sp = STACK
        state.memory.store(OBJECT,obj)
        state.memory.store(PAYLOAD,payload)
        state.memory.store(WRAPPER,bytes(0x24))
        state.memory.store(WRAPPER+0x1C,struct.pack('<I',PAYLOAD))
        events = []
        def write(s):
            address = s.solver.eval(s.inspect.mem_write_address)
            if 0xB6000000 <= address < 0xB6001000:
                assert not s.inspect.mem_write_expr.symbolic
                events.append([address,s.solver.eval(s.inspect.mem_write_length),s.solver.eval(s.inspect.mem_write_expr)])
        state.inspect.b('mem_write',when=angr.BP_BEFORE,action=write)
        for address in (setter,writer):
            state.regs.pc, state.regs.ra = address, RETURN
            state.regs.a0, state.regs.a1 = OBJECT, WRAPPER
            sim = project.factory.simgr(state)
            sim.explore(find=RETURN,n=128)
            assert len(sim.found)==1 and not sim.active and not sim.errored
            state = sim.found[0]
            assert state.solver.eval(state.regs.sp)==STACK
            actual = state.memory.load(OBJECT,len(expected))
            assert not actual.symbolic and state.solver.eval(actual,cast_to=bytes)==expected
        assert events==result['mmio_writes'], f'{setter:#x}: MMIO mismatch'
    return reference()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error('output must not exist')
    result=replay(args.elf)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('2 FIPLIB setter/writer chains: complete object bytes and 28 ordered MMIO writes PASS')


if __name__=='__main__':
    main()
