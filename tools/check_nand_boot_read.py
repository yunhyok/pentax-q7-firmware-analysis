"""Replay Q7 header consumption, information-get, separate geometry and supplied boot-read calls."""
import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct
from unittest.mock import patch

import check_nand_headers as c
import check_main_burn as m
from build_analysis_elf import PLAIN
from check_burn_storage import arguments,num,u32,put_u32,read_bytes
from check_q7_portability import execute
from check_isp_registers import ELF_SHA256,load_project
from decode_segments import inspect as decode_segments
from inspect_q7 import parse_elf
from q7_symbols import SHA

REPORT_SHA256 = "a0f2ee83b303db6e04d7e4023769ae9ef0064834685420cf4d7f70543659cfa8"
RETRY,INFO_RETURN,DRIVER = 0x8006A158,0x805E549C,0x8006423C
BOOT,MEDIA,FCU = 0x80084558,0x8007EA44,0x8007E630
CONTEXT_GLOBAL,CONTEXT = 0x8008C14C,m.MEDIA_INFO

E03_PINS = (
    (0x80053124, 40, "98c6b1a5cdf8944f21385b5ba7bae6d4b9b8dd926377be22544c248893a44b10"),
    (0x80053E70, 168, "90866d43de0bd7b82290e2d1fe57eeb7bb4c75345459b8ce6823641c7126174d"),
    (0x80055838, 116, "64c799f7f4acdc2454dd4a17319e9b375eda090715c9bc0b643a7dd41e89dce8"),
    (0x80059A59, 1, "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
    (0x80064040, 508, "986f708881f150d57c5507df83b847069d1f4b0d1fab78f2fb73af5eb6d54cb8"),
    (0x8006423C, 520, "94e9b58a4f9931a5722b1a9117b93529aeecd52741e8a1b201cf0b73e8a3c913"),
    (0x8006444C, 8, "89c6f1f94ee704e19d46a68511eb96882092f79b9f2b4a29f02765af1b34ee59"),
    (0x80066A5C, 632, "d13296f86fd85954fa8e8bf41164a6c5e78e63f5966b208e6c35f6ef1c146597"),
    (0x80067700, 56, "c2d83767793fa790ea2847ca3dda66c9c9485ed7aa5c79762dab83ea6b61214e"),
    (0x80069B94, 352, "4c411583ece7fa9ba0220e6dfc99a6275e55ba94d947083b725e9b785c14020d"),
    (0x8006A0C4, 148, "4f1ee6c2bca610b3c656fbd3304abf29d24944d57255fe18397ec1a0ccba2aac"),
    (0x8006A158, 400, "953b47aa3c49d55e17afa31dfbc9c2faf8c74c9d47b329771d067d3afef5fc99"),
    (0x8007E630, 1044, "ce97dbfafba035a6ac7469b3d89936ce601c58003654908d07fcdb2bc19c1d4b"),
    (0x8007EA44, 1636, "9e107552e35b4715093870db138e8288e99c5bd9b895f9d12d131a75d32e038c"),
    (0x8008389C, 432, "0b503bbea6f599a85454fedbf1080d03a0d2b6a8f2e20867bea50b3f666668ef"),
    (0x80083BE0, 52, "99e76b3145f775a7645a51c60611183c3d99db01483eb54ab22c84b89641e5e7"),
    (0x800840FC, 72, "d6f7d5b55bfc1a66c38f9c5ed1ea6b7dc938d4b10fedf0efb54f28aadacb5b7e"),
    (0x80084558, 1120, "a29428924f23d62e96b75fd57f6f539d0a1fb9085a32e2da8442f824e13b1a3c"),
    (0x80084BF4, 384, "2aaa6139ed896bd0b8668ce32cc48916ea650873aa32a26390b48a69bdf37456"),
    (0x80085004, 28, "8a5c9911cc890eb4b1ce42ab0c8bb3f06b4c18ddd62f7f86ad55510a3b36600c"),
    (0x8008C14C, 4, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
    (0x8008C2DC, 1, "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"),
    (0x8008CE5C, 80, "75bdcaf1540ac552d856c44604b652901ce9d6e80a0647725bce35a9187ae02f"),
)

HEADER_CASES=[
 dict(name='clear-zero',fourth=0,first_word=0,second_word=0,redirect=False,fail=False),
 dict(name='clear-pattern',fourth=0,first_word=0x13579BDF,second_word=0,redirect=False,fail=False),
 dict(name='clear-allones',fourth=0,first_word=0xFFFFFFFF,second_word=0,redirect=False,fail=False),
 dict(name='clear-pattern-stride256',fourth=1,first_word=0x13579BDF,second_word=0,redirect=False,fail=False),
 dict(name='redirect-pattern',fourth=0,first_word=0x11111111,second_word=0x2468ACE0,redirect=True,fail=False),
 dict(name='redirect-second-fails',fourth=0,first_word=0x11111111,second_word=0x2468ACE0,redirect=True,fail=True),
]
BOOT_CASES=[
 dict(name='null-context-control',word=0x123,kind=None,fourth=0,redirect=False),
 dict(name='kind1-zero',word=0,kind=1,fourth=0,redirect=False),
 dict(name='kind1-unaligned',word=0x123,kind=1,fourth=0,redirect=False),
 dict(name='kind1-pattern',word=0x13579BDF,kind=1,fourth=0,redirect=False),
 dict(name='kind1-allones',word=0xFFFFFFFF,kind=1,fourth=0,redirect=False),
 dict(name='kind1-unaligned-stride256',word=0x123,kind=1,fourth=1,redirect=False),
 dict(name='kind1-redirect-selected',word=0x2468ACE0,kind=1,fourth=0,redirect=True),
]



def source_evidence(firmware,elf):
    """Check original E03 bytes and freshly decoded E05 before loading an engine."""
    layout,_=parse_elf(elf,0)
    def elf_range(address,size):
        seg=next(s for s in layout['segments'] if s['type']==1 and s['virtual_address']<=address and address+size<=s['virtual_address']+s['file_size'])
        off=seg['file_offset']+address-seg['virtual_address']
        return elf[off:off+size],off
    ranges=[]
    for address,size,expected in E03_PINS:
        original,va,_=next(s for s in PLAIN if s[1]<=address and address+size<=s[1]+s[2])
        off=original+address-va
        raw=firmware[off:off+size];analysis,elf_off=elf_range(address,size)
        assert len(raw)==size and raw==analysis and sha256(raw).hexdigest()==expected
        ranges.append(dict(address=hex(address),size=size,sha256=expected,original_file_offset=hex(off),analysis_elf_offset=hex(elf_off),byte_equal=True))
    manifest,segments=decode_segments(firmware)
    address,size=0x805E53F0,216
    seg=next(s for s in manifest['segments'] if s['name'].startswith('E05') and s['virtual_address']<=address and address+size<=s['virtual_address']+s['decoded_size'])
    assert seg['decoded_sha256']=='a411eecc87e46c88cd58548fdd677a20419494110b2c1b19bf1852ad4bfa78b2'
    off=address-seg['virtual_address'];raw=segments[seg['name']][off:off+size]
    analysis,elf_off=elf_range(address,size)
    assert raw==analysis and sha256(raw).hexdigest()=='3d221a58da282947152e6ee459be133522ca45fb967fcb8b35faea4e047f578c'
    return dict(prefix=c.source_evidence(firmware,elf),selected_e03_ranges=ranges,
        decoded_burn=dict(address=hex(address),size=size,sha256=sha256(raw).hexdigest(),
            decoded_segment_sha256=seg['decoded_sha256'],decoded_segment_offset=hex(off),analysis_elf_offset=hex(elf_off),byte_equal=True),
        range_boundary='Address-selected ranges, not ELF typed-function size declarations. Original E03 byte checks and fresh E05 stream decode; no firmware bytes included.')


def fields(st):
    offsets=(0,0x198,0x1C8,0x1CC,0x1D4,0xBC8,0xBCC,0xBD0,0xBEC,0xBF4,0xC10,0xC18,0xC88,0xC8C)
    row={hex(o):u32(st,m.HANDLE+o) for o in offsets}
    row['0xc14']=int.from_bytes(read_bytes(st,m.HANDLE+0xC14,2),'little')
    return row


def run_header_case(p,angr,header,spec,on_information=None):
    def body(p,angr,st,before,entry,unused):
        stride=int(entry['arguments'][2],16); aligned=(0x123//stride)*stride
        buffers=[bytearray(0x400),bytearray(0x400)]
        struct.pack_into('<I',buffers[0],0x14,(0x80000000 if spec['redirect'] else 0)|0x123)
        for b,v in zip(buffers,(spec['first_word'],spec['second_word'])):struct.pack_into('<I',b,0x200,v)
        expected=[(6,0,1,0),(4,0,2,0)]
        if spec['redirect']:expected.extend([(6,aligned,1,0),(4,aligned,2,7 if spec['fail'] else 0)])
        io,allocations,releases,trace,suffix_models=[],[],[],[],[]
        prefix_count=len(list(st.history.bbl_addrs)); initial_sp=num(st,st.regs.sp)

        class Nand(angr.SimProcedure):
            def run(self):
                dev,handle,op,pos,count,data,extra=arguments(self.state)
                size=u32(self.state,num(self.state,self.state.regs.sp)+28)
                assert len(io)<len(expected)
                eop,epos,ecount,status=expected[len(io)]
                assert (dev,handle,op,pos,count)==(1,m.HANDLE,eop,epos,ecount)
                assert num(self.state,self.state.regs.ra)==0x80053F0C
                supplied=b'\xff'*16 if op==6 else bytes(buffers[0 if len(io)==1 else 1])
                if op==6:assert (data,size)==(0,16) and extra!=0
                else:assert (data,extra,size)==(m.INSTALLED,0,0)
                if status==0:self.state.memory.store(extra if op==6 else data,supplied,size=len(supplied))
                io.append(dict(operation=op,position=pos,count=count,status=status,
                    data=hex(data),extra=hex(extra),extra_size=size,
                    supplied_sha256=sha256(supplied).hexdigest() if status==0 else None))
                return status

        class Allocate(angr.SimProcedure):
            def run(self):
                assert arguments(self.state)[:5]==[0,0x400,0,0x80063A88,0x6CB]
                assert not allocations
                self.state.memory.store(m.INSTALLED,bytes(0x400),size=0x400)
                allocations.append(dict(address=hex(m.INSTALLED),size=0x400))
                return m.INSTALLED

        class Release(angr.SimProcedure):
            def run(self):
                args=arguments(self.state)[:4];ra=num(self.state,self.state.regs.ra)
                assert args==([0,m.INSTALLED,0x80063A88,0x6E1] if spec['fail'] else [0,m.INSTALLED,0x8008EF6C,0x171B])
                assert ra==(0x80056744 if spec['fail'] else 0x8008413C)
                releases.append(dict(api='0x8000c598',arguments=[hex(x) for x in args],return_address=hex(ra),actual_free=False))
                return 0

        watched={m.INSTALLED+0x200,m.HANDLE+0xC10,m.HANDLE+0xBF4,m.HANDLE+0xC14,m.HANDLE+0xC88,m.HANDLE+0xC8C,m.HANDLE+0x1C8,m.HANDLE+0x1CC}
        def read(st):
            a=st.inspect.attrs;addr=num(st,a.mem_read_address)
            if addr in watched:
                trace.append(dict(kind='read',vex_instruction_context_pc=hex(num(st,st.scratch.ins_addr)),state_context_pc=hex(st.addr),address=hex(addr),size=num(st,a.mem_read_length),value=num(st,a.mem_read_expr)))
        def write(st):
            a=st.inspect.attrs;addr=num(st,a.mem_write_address)
            if addr in watched:
                trace.append(dict(kind='write',vex_instruction_context_pc=hex(num(st,st.scratch.ins_addr)),state_context_pc=hex(st.addr),address=hex(addr),size=num(st,a.mem_write_length),value=num(st,a.mem_write_expr)))
        st.inspect.b('mem_read',when=angr.BP_AFTER,action=read)
        st.inspect.b('mem_write',when=angr.BP_BEFORE,action=write)
        p.hook(m.NAND_EX,Nand(num_args=0),replace=True)
        p.hook(0x8000BF28,Allocate(num_args=0));p.hook(0x8000C598,Release(num_args=0))
        returned=c.advance(p,st,c.HEADER_RETURN,angr,steps=1000)
        assert num(returned,returned.regs.sp)==initial_sp
        assert num(returned,returned.regs.v0)==(0 if spec['fail'] else m.INSTALLED)
        assert len(io)==len(expected)
        returned_fields=fields(returned)
        assert returned_fields['0xc10']==0 and returned_fields['0xbf4']==0x100000
        effective=spec['second_word'] if spec['redirect'] else spec['first_word']
        result=dict(case=spec,entry=entry,header_return=hex(num(returned,returned.regs.v0)),
            io=io,allocations=allocations,releases=releases,header_return_fields=returned_fields)

        if spec['fail']:
            failed=c.advance(p,returned,0x80066B88,angr,steps=1000)
            assert num(failed,failed.regs.v0)==0x90 and u32(failed,m.HANDLE+0xC10)==0 and u32(failed,m.HANDLE+0x1CC)==0x90
            assert len(releases)==1 and not any(t['address']==hex(m.INSTALLED+0x200) for t in trace)
            result.update(stop_before=hex(failed.addr),tl_media_init_result=0x90,trace=trace,fields=fields(failed),
                total_vex_events=len(list(failed.history.bbl_addrs)[before:]),geometry_executed=False)
            return result

        retry=c.advance(p,returned,RETRY,angr,steps=1000)
        assert num(retry,retry.regs.a0)==1 and num(retry,retry.regs.ra)==0x80066B88
        assert len(releases)==1 and u32(retry,m.HANDLE+0xC10)==effective
        assert any(t['kind']=='write' and t['vex_instruction_context_pc']=='0x80084128' and t['address']==hex(m.HANDLE+0xC10) and t['value']==effective for t in trace)
        h=list(retry.history.bbl_addrs)[prefix_count:]
        assert 0x80084120 in h and 0x80083C0C in h
        assert 0x80084BC0 not in h and 0x80064040 not in h
        result['retry_entry']=dict(stop_before=hex(retry.addr),arguments=[hex(num(retry,retry.regs.a0))],return_address=hex(num(retry,retry.regs.ra)),
            fields=fields(retry),total_vex_events=len(list(retry.history.bbl_addrs)[before:]),trace=list(trace))

        class Suffix(angr.SimProcedure):
            def run(self,*,api):
                args=arguments(self.state);ra=num(self.state,self.state.regs.ra)
                if api==RETRY:assert args[0]==1 and ra==0x80066B88
                elif api==0x800CE6D4:assert args[:3]==[m.HANDLE+8,0x8008CEE4,1]
                elif api==0x800CEF4C:assert args[:2]==[m.HANDLE+8,0xFFFFFFFF]
                else:assert api==0x800D0264 and args[0]==m.HANDLE+8
                suffix_models.append(dict(api=hex(api),arguments=[hex(v) for v in args[:(3 if api==0x800CE6D4 else 2 if api==0x800CEF4C else 1)]],return_address=hex(ra),result=0))
                return 0

        for api in (RETRY,0x800CE6D4,0x800CEF4C,0x800D0264):p.hook(api,Suffix(num_args=0,api=api))
        info=c.advance(p,retry,INFO_RETURN,angr,steps=1000)
        info_history=list(info.history.bbl_addrs)[prefix_count:]
        assert num(info,info.regs.v0)==0
        assert u32(info,m.HANDLE)==0x4D454448
        assert u32(info,m.HANDLE+0xC10)==effective and u32(info,m.HANDLE+0xBF4)==0x100000
        assert (u32(info,m.HANDLE+0xC88),u32(info,m.HANDLE+0xC8C))==(stride,0x100000)
        assert all(pc in info_history for pc in (0x80066BD4,0x80069B94,0x80069BF0))
        assert not any(pc in info_history for pc in (0x80084558,0x80084BC0,0x80064040,m.HOST_ACK,m.BURN_NAND))
        result['information_get']=dict(stop_before=hex(info.addr),result=0,fields=fields(info),trace=list(trace),
            total_vex_events=len(list(info.history.bbl_addrs)[before:]),suffix_models=list(suffix_models),geometry_executed=False)

        if on_information is not None: on_information(info.copy())

        # Separate supplied request: not the next request observed in the native open stream.
        separate=info.copy();trace.clear()
        put_u32(separate,m.HANDLE+0x1C8,9)
        separate.regs.sp=m.STACK_TOP
        separate_before=len(list(separate.history.bbl_addrs))
        separate=execute(p,separate,DRIVER,m.HANDLE,steps=1000)
        assert u32(separate,m.HANDLE+0xC10)==effective
        assert u32(separate,m.HANDLE+0xBF4)==0x100000 and u32(separate,m.HANDLE+0x1CC)==0
        assert u32(separate,m.HANDLE+0xBC8)==1041 and u32(separate,m.HANDLE+0x198)==stride
        assert num(separate,separate.regs.v0)==1
        assert 0x80064040 in list(separate.history.bbl_addrs)[separate_before:]
        assert not any(t['address']==hex(m.HANDLE+0xC10) for t in trace)
        result['separate_request9']=dict(scope='Explicit supplied driver request9 on an information-get snapshot copy; PC/RA/SP reset, not a continuation of FileX requests.',
            supplied_request=9,entry=hex(DRIVER),stop_before=hex(m.RETURN_PC),return_value=1,fields=fields(separate),trace=list(trace),
            vex_events=len(list(separate.history.bbl_addrs)[separate_before:]),geometry_executed=True)
        return result

    # This CLI runs cases serially; the existing header continuation is process-global.
    with patch.object(c,'header_case',body):
        return c.native_open_case(p,angr,header,spec['fourth'],scenario=spec['name'])

def step_to(p,st,targets):
    sim=p.factory.simgr(st,save_unconstrained=True)
    sim.explore(find=targets,n=1000)
    assert len(sim.found)==1 and not(sim.active or sim.errored or sim.unconstrained or sim.deadended),(sim,sim.errored)
    return sim.found[0]


def snapshot(st):
    return dict(pc=hex(st.addr),arguments=[hex(x) for x in arguments(st)+[u32(st,num(st,st.regs.sp)+28)]],
        return_address=hex(num(st,st.regs.ra)),sp=hex(num(st,st.regs.sp)))


def run_boot_case(angr,elf,header,case):
    origin=dict(name='phase18-header-control',fourth=case['fourth'],first_word=0x11111111 if case['redirect'] else case['word'],
        second_word=case['word'] if case['redirect'] else 0,redirect=case['redirect'],fail=False)
    p=load_project(elf);saved=[]
    prefix=run_header_case(p,angr,header,origin,on_information=saved.append)
    assert len(saved)==1
    st=saved[0]
    assert u32(st,m.HANDLE+0xC10)==case['word']
    before_globals={hex(a):u32(st,a) for a in (CONTEXT_GLOBAL,m.HANDLE+0x1C8,m.HANDLE+0x1D0,m.HANDLE+0x1D4,m.HANDLE+0xC10,m.HANDLE+0xC24,CONTEXT)}
    assert before_globals[hex(CONTEXT_GLOBAL)]==0
    assert before_globals[hex(m.HANDLE+0x1D0)]==m.OPEN_RAM
    assert before_globals[hex(m.HANDLE+0x1D4)]==0x80000000
    assert before_globals[hex(m.HANDLE+0xC24)]==0 and before_globals[hex(CONTEXT)]==1
    assert p.loader.memory.load(0x80059A59,1)==b'\0'
    header_sha=sha256(read_bytes(st,m.INSTALLED,0x400)).hexdigest()
    initial_destination_sha=sha256(read_bytes(st,m.OPEN_RAM,0x2000)).hexdigest()
    context_sha=sha256(read_bytes(st,CONTEXT,0xC90)).hexdigest()
    baseline_reads=[]
    def watch(st):
        attrs=st.inspect.attrs;address=num(st,attrs.mem_read_address)
        if address in (m.HANDLE+0xC10,CONTEXT_GLOBAL,CONTEXT,m.OPEN_RAM+1):
            baseline_reads.append(dict(address=hex(address),size=num(st,attrs.mem_read_length),value=num(st,attrs.mem_read_expr),
                vex_instruction_context_pc=hex(num(st,st.scratch.ins_addr)),state_context_pc=hex(st.addr)))
    st.inspect.b('mem_read',when=angr.BP_AFTER,action=watch)
    # Supplied call context: this request is skipped by the observed special FileX open.
    put_u32(st,m.HANDLE+0x1C8,5)
    put_u32(st,CONTEXT_GLOBAL,0 if case['kind'] is None else CONTEXT)
    st.regs.pc,st.regs.ra,st.regs.sp=DRIVER,m.RETURN_PC,m.STACK_TOP
    st.regs.a0,st.regs.a1=m.HANDLE,1
    before=len(list(st.history.bbl_addrs))
    boot=step_to(p,st,(BOOT,m.RETURN_PC))
    assert boot.addr==BOOT
    boot_args=arguments(boot)[:2]
    assert boot_args==[m.HANDLE,0 if case['kind'] is None else CONTEXT]
    assert num(boot,boot.regs.ra)==0x80064310
    checkpoints=dict(boot=snapshot(boot))
    media=step_to(p,boot,(MEDIA,m.RETURN_PC))
    if case['kind'] is None:
        assert media.addr==m.RETURN_PC and num(media,media.regs.v0)==0xF2
        assert u32(media,m.HANDLE+0x1CC)==0xF2 and num(media,media.regs.sp)==m.STACK_TOP
        assert MEDIA not in list(media.history.bbl_addrs)[before:] and m.NAND_EX not in list(media.history.bbl_addrs)[before:]
        final=media
    else:
        assert media.addr==MEDIA
        assert arguments(media)+[u32(media,num(media,media.regs.sp)+28)]==[m.HANDLE,CONTEXT,4,case['word'],1,m.OPEN_RAM,0,0]
        assert num(media,media.regs.ra)==0x80084808
        checkpoints['media_operation']=snapshot(media)
        fcu=step_to(p,media,FCU)
        assert arguments(fcu)==[m.HANDLE,1,4,case['word'],1,m.OPEN_RAM,0]
        assert num(fcu,fcu.regs.ra)==0x8007EC08
        checkpoints['fcu_operation']=snapshot(fcu)
        wrapper=step_to(p,fcu,m.NAND_WRAPPER)
        wa=arguments(wrapper)
        assert wa[:5]==[m.HANDLE,4,case['word'],1,m.OPEN_RAM] and wa[6]==16
        assert wa[5]==num(fcu,fcu.regs.sp)-0x78+0x20 and num(wrapper,wrapper.regs.ra)==0x8007E9C0
        checkpoints['nand_wrapper']=snapshot(wrapper)
        final=step_to(p,wrapper,m.NAND_EX)
        fa=arguments(final)+[u32(final,num(final,final.regs.sp)+28)]
        assert fa==[1,m.HANDLE,4,case['word'],1,m.OPEN_RAM,wa[5],16]
        assert num(final,final.regs.ra)==0x80053F0C
        checkpoints['nand_ex']=snapshot(final)
    assert any(t['address']==hex(m.HANDLE+0xC10) and t['value']==case['word'] for t in baseline_reads)
    history=list(final.history.bbl_addrs)[before:]
    assert m.BURN_NAND not in history and m.HOST_ACK not in history
    final_destination_sha=sha256(read_bytes(final,m.OPEN_RAM,0x2000)).hexdigest()
    assert final_destination_sha==initial_destination_sha
    return dict(case=case,scope='Separate supplied request5 and register restart on a phase17 information-return snapshot. Not a connected FileX request.',
        prefix_header=prefix['case'],prefix_information_get=prefix['information_get'],prefix_releases=prefix['releases'],
        selected_header_sha256=header_sha,before_globals=before_globals,synthetic_context_sha256=context_sha,
        supplied_changes=dict(request_at_handle_1c8=5,context_global=hex(CONTEXT_GLOBAL),context_pointer=hex(0 if case['kind'] is None else CONTEXT),context_kind=case['kind'],
            pc=hex(DRIVER),ra=hex(m.RETURN_PC),sp=hex(m.STACK_TOP),a0=hex(m.HANDLE),a1=1),
        checkpoints=checkpoints,reads=baseline_reads,stop_before=hex(final.addr),request_vex_events=len(history),
        result=num(final,final.regs.v0) if final.addr==m.RETURN_PC else None,
        driver_status_at_stop=u32(final,m.HANDLE+0x1CC),nand_response_supplied=False,
        initial_destination_sha256=initial_destination_sha,final_destination_sha256=final_destination_sha)

def replay(firmware,elf):
    if not __debug__:
        raise RuntimeError('replay requires assertions')
    if sha256(firmware).hexdigest()!=SHA:
        raise ValueError('expected SHA-pinned Q7 v1.01 firmware')
    elf_bytes=elf.read_bytes()
    if sha256(elf_bytes).hexdigest()!=ELF_SHA256:
        raise ValueError('expected SHA-pinned Q7 analysis ELF')
    source=source_evidence(firmware,elf_bytes)
    header=firmware[m.UPDATE_HEADER_OFFSET:m.UPDATE_HEADER_OFFSET+m.UPDATE_HEADER_SIZE]
    assert len(header)==192
    import angr
    header_rows=[run_header_case(load_project(elf),angr,header,case) for case in HEADER_CASES]
    boot_rows=[run_boot_case(angr,elf,header,case) for case in BOOT_CASES]
    assert [r['information_get']['total_vex_events'] for r in header_rows[:-1]]==[385,385,385,388,401]
    assert header_rows[-1]['total_vex_events']==383
    assert [r['separate_request9']['vex_events'] for r in header_rows[:-1]]==[17]*5
    assert [r['request_vex_events'] for r in boot_rows]==[10]+[23]*6
    return dict(schema_version=1,input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,
        engine=f'angr {angr.__version__} / original MIPS32 little-endian / VEX',source=source,
        scope='Six header-consumption controls (five information-get successes and one failure); five separate supplied request9 controls; seven separate supplied request5 controls. These are distinct experiments, not one FileX request sequence.',
        runtime='Analysis ELF segments are RWX. Synthetic RAM and globals: 81547f10=0,8008c2dc=0 byte,8008c2f4=0 initially; writes to the latter two allowed. No physical memory permission or alias model.',
        trace_pc_semantics='VEX callback PCs can attribute MIPS delay slots to preceding branches. Resolve exact native instruction PCs against original source bytes.',
        abi_slots='Snapshots store eight raw ABI slots. Meaningful call arguments: TlBootRead first2; TlFcuOperation and FcuNandOperation first7; TlMediaOperation and FcuNandOperationEx all8. Other slots are incidental.',
        modeled_apis=dict(prefix=m.NATIVE_OPEN_MODELS,
            header='Synthetic ID, FF spare, two synthetic 0x400-byte headers and optional status7; allocate one zeroed buffer; record release without actual free.',
            suffix='After original retry entry, supply success for TlInitRetryInfo and ThreadX semaphore create/get/put, validating arguments.',
            request5='No added API response model. Supply request5 and a null or kind1 context pointer; reset PC/RA/SP. Positive cases stop before the existing NAND Ex hook executes. Null context uses existing diagnostics.'),
        static_dispatch=dict(burn_seventh_argument='0x80000000',request5_skipped=True,
            nonsentinel='Initial request4 must succeed through TlDriverInit before FileX calls request5. Kind1 context is a separate condition. This natural nonsentinel path was not replayed.',
            allones='Argument7=0xffffffff still calls request5 after successful request4; a later FileX fallback checks this value.'),
        header_information=dict(cases=header_rows),
        boot_read=dict(scope='Each case freshly reexecutes the header prefix with deliberate words and copies state at805e549c. Request9 runs on another copy and is not a predecessor of request5. hNandTlInfo registration and TlDriverInit success are not established.',cases=boot_rows),
        limitations=[
            'No actual NAND ID/header/response, physical sector/page/block units, camera boot, write or recovery established.',
            'Position forwarding, including ffffffff, does not establish valid address ranges or successful data reads.',
            'Positive request5 stops before NAND Ex body or response, retry and partition parsing. Its driver status90 is a staged value, not a completed error result.',
            'Null context still requires readable DATA[1], which is loaded before the null check.',
            'Geometry request9 and boot-read request5 are independent supplied-call experiments with register restarts.',
            'The original sentinel FileX path skips TlDriverInit, geometry and request5. No natural nonsentinel open or native retry/semaphore implementation is executed.',
            'Flat virtual addresses and synthetic pointers; KSEG aliases, TLB, caches and DMA are not modeled.'])


def validate_report(report):
    if not __debug__:
        raise RuntimeError('validation requires assertions')
    digest=sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    assert digest==REPORT_SHA256,'NAND boot-read observations differ'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('firmware',type=Path)
    parser.add_argument('elf',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not __debug__:
        parser.error('replay requires assertions')
    if lexists(args.output):
        parser.error('output must not exist')
    report=replay(args.firmware.read_bytes(),args.elf)
    validate_report(report)
    try:
        with args.output.open('x',encoding='utf-8',newline='\n') as out:
            json.dump(report,out,indent=2);out.write('\n')
    except FileExistsError:
        parser.error('output appeared while replaying')
    print('PASS original MIPS/VEX: 6 header/info, 5 separate geometry and 7 separate boot-read controls')


if __name__=='__main__':main()
