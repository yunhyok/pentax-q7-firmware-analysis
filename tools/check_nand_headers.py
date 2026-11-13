"""Replay bounded Q7 NAND ID parsing, header entry and one header redirect branch."""
import argparse
from hashlib import sha256
import json
from os.path import lexists
from pathlib import Path
import struct

import check_main_burn as m
from build_analysis_elf import PLAIN
from check_burn_storage import arguments, num, read_bytes, u32
from check_isp_registers import ELF_SHA256, load_project
from check_q7_portability import new_state, guard, execute
from inspect_q7 import parse_elf
from q7_symbols import SHA


REPORT_SHA256 = "eb47c874692215bc59751083bc025801feef92c19969d36a8df99390ecc49d7b"
PARSER, ID_TABLE, HEADER_ENTRY, HEADER_RETURN = 0x800556BC, 0x80063BA4, 0x80056644, 0x80084114
PARSER_ID, PARSER_HANDLE = 0x24000000, 0x24001000
FUNCTIONS = (
    ('FcuNandParseId',PARSER,896),('TlNandParseId',0x80081C98,96),
    ('device-id-jump-table',ID_TABLE,764),('_fx_nand_driver',0x8006423C,520),
    ('_fx_nand_non_seq_read_driver',0x8006444C,8),('TlMediaInit',0x8008389C,3260),
    ('FcuMediaInfoGetHeader',HEADER_ENTRY,304),('FcuNandFindAndReadBootHeader',0x80055B9C,184),
    ('FcuNandFindAndReadHeader',0x80055A3C,352),('FcuNandOperation',m.NAND_WRAPPER,168),
    ('_fx_nand_get_geometry',0x80064040,508),
)
WORDS = {
    'parser_capacity_and_stride':(0x800557A0,0x800557AC,0x800557B0,0x80055838,0x80055844,0x80055854,0x80055894,0x800558A4,0x800559EC,0x800559F4),
    'native_flags_and_header_call':(0x80064450,0x800643A8,0x800643AC,0x80083BE4,0x800840FC,0x80084104,0x8008410C,0x80084110,0x80084118,0x8008411C,0x80084120,0x80084128),
    'allocation_and_header_selector':(0x80056670,0x80056678,0x8005667C,0x800566F8,0x80056710,0x80056724,0x8005673C,0x80056764),
    'boot_header_redirect':(0x80055BB4,0x80055BCC,0x80055BD8,0x80055C10,0x80055C20,0x80055C28,0x80055C2C,0x80055C30,0x80055C34,0x80055C3C,0x80055C40,0x80055C44),
    'spare_data_and_failure':(0x80055A68,0x80055A84,0x80055A8C,0x80055A98,0x80055AAC,0x80055AB4,0x80055ABC,0x80055AC8,0x80055B50,0x80055B5C,0x80055B64,0x80055B6C),
    'geometry_calculation_static_only':(0x80064040,0x80064094,0x80064098,0x800640A4,0x800640AC,0x800640B4,0x80064188,0x80064194,0x80064198,0x800641E8,0x80064224,0x8006422C,0x80064230),
}
PARSER_CASES = (
    ('unsupported-manufacturer',0xFF,0xDC,0,1,0x90),('unsupported-device',0xEC,0,0,1,0x90),
    ('dc-basic',0xEC,0xDC,0,1,0),('dc-distinct-byte3',0xEC,0xDC,1,1,0),
    ('dc-equal-byte3',0xEC,0xDC,0xDC,1,0),('dc-kind102',0xEC,0xDC,1,0x102,0),
    ('dc-unsupported-kind',0xEC,0xDC,0,2,0xF2),('ad-a1',0xAD,0xA1,0,1,0),
    ('ec-e3',0xEC,0xE3,0,1,0),('98-e3-reject',0x98,0xE3,0,1,0x90),
    ('98-6b',0x98,0x6B,0,1,0),('ec-6b-reject',0xEC,0x6B,0,1,0x90),
)


def source_evidence(firmware, elf):
    """Compare selected original E03 ranges against the pinned analysis ELF."""
    layout,_=parse_elf(elf,0)

    def original(address,size):
        offset,va,_=next(s for s in PLAIN if s[1]<=address and address+size<=s[1]+s[2])
        offset+=address-va
        data=firmware[offset:offset+size]
        segment=next(s for s in layout['segments'] if s['type']==1 and s['virtual_address']<=address and address+size<=s['virtual_address']+s['file_size'])
        elf_offset=segment['file_offset']+address-segment['virtual_address']
        assert data==elf[elf_offset:elf_offset+size]
        return data,offset,elf_offset

    ranges=[]
    for name,address,size in FUNCTIONS:
        data,offset,elf_offset=original(address,size)
        ranges.append(dict(name=name,address=hex(address),size=size,sha256=sha256(data).hexdigest(),
            original_file_offset=hex(offset),analysis_elf_offset=hex(elf_offset),byte_equal=True))
    words=[]
    for role,addresses in WORDS.items():
        for address in addresses:
            data,offset,elf_offset=original(address,4)
            words.append(dict(role=role,address=hex(address),word=f'0x{int.from_bytes(data,"little"):08x}',
                original_file_offset=hex(offset),analysis_elf_offset=hex(elf_offset)))
    address=ID_TABLE+(0xF1-0x33)*4
    data,offset,_=original(address,4)
    assert int.from_bytes(data,'little')==0x8005590C
    return dict(selected_ranges=ranges,words=words,
        range_boundary='Address-selected ranges; not ELF typed-function size declarations.',
        f1=dict(device_id_byte='0xf1',table_entry=hex(address),target='0x8005590c',original_file_offset=hex(offset),
                meaning='Static dispatch only; physical device meaning and installed ID remain unknown.'))


def parser_cases(p,angr):
    table=p.loader.memory.load(ID_TABLE,764)
    groups={}
    for ident,target in enumerate(struct.unpack('<191I',table),0x33):
        groups.setdefault(hex(target),[]).append(hex(ident))
    assert len(groups['0x80055784'])==161
    rows=[]
    for name,manufacturer,device,fourth,kind,expected in PARSER_CASES:
        st=new_state(p,angr)
        supplied=bytes([manufacturer,device,0,fourth,0,0,0,0])
        st.memory.store(PARSER_ID,supplied,inspect=False)
        st.memory.store(PARSER_HANDLE,bytes(0xC90),inspect=False)
        guard(st,angr,((PARSER_HANDLE,PARSER_HANDLE+0xC90),),((PARSER_ID,PARSER_ID+8),(ID_TABLE,ID_TABLE+764)))
        st=execute(p,st,PARSER,PARSER_ID,PARSER_HANDLE,kind,steps=100)
        result=num(st,st.regs.v0)
        assert result==expected,(name,result)
        fields={hex(offset):int.from_bytes(read_bytes(st,PARSER_HANDLE+offset,size),'little')
            for offset,size in ((0x1CC,4),(0xBF4,4),(0xC00,1),(0xC01,1),(0xC0C,4),(0xC14,2),(0xC18,4),(0xC2C,4))}
        assert fields['0x1cc']==(0 if result==0 else 0x90)
        rows.append(dict(name=name,supplied_id_hex=supplied.hex(),kind=kind,result=result,
                         fields=fields,vex_block_events=len(list(st.history.bbl_addrs))))
    f={r['name']:r['fields'] for r in rows}
    assert f['dc-basic']['0xc18']==f['dc-equal-byte3']['0xc18']==3
    assert f['dc-distinct-byte3']['0xc18']==5
    assert f['dc-basic']['0xc14']==5 and f['dc-distinct-byte3']['0xc14']==8
    assert f['dc-basic']['0xbf4']==0x100000 and f['dc-kind102']['0xbf4']==0xF9C80
    assert f['ad-a1']['0xc18']==0x204
    assert f['ec-e3']['0xbf4']==f['98-6b']['0xbf4']==0x2000
    return dict(scope='Isolated original parser with synthetic ID bytes and zeroed handle; no API hooks.',
                device_table_groups=groups,cases=rows)


def advance(p,st,target,angr,*,steps):
    sim=p.factory.simgr(st,save_unconstrained=True)
    sim.explore(find=target,avoid=(m.RETURN_PC,m.BURN_NAND),n=steps)
    assert len(sim.found)==1 and not(sim.active or sim.errored or sim.unconstrained or sim.deadended or sim.avoid),(sim,sim.errored)
    return sim.found[0]


def native_open_case(p,angr,header,fourth,scenario=None):
    supplied=bytes([0xEC,0xDC,0,fourth,0,0,0,0])
    step,flag=(256,5) if fourth else (32,3)

    def after_id_request(p,angr,st,events,before,prefix):
        first_args=[int(x,16) for x in prefix['arguments']]
        initial_flags=u32(st,m.HANDLE+0xC18)

        class Response(angr.SimProcedure):
            def run(self):
                assert arguments(self.state)==first_args[:7]
                assert u32(self.state,num(self.state,self.state.regs.sp)+28)==first_args[7]
                self.state.memory.store(first_args[5],supplied,size=8)
                events.append(dict(kind='supplied-id-response',status=0,id_hex=supplied.hex()))
                return 0

        p.hook(m.NAND_EX,Response(num_args=0))
        stop=advance(p,st,HEADER_ENTRY,angr,steps=m.STEP_LIMIT)
        args=arguments(stop)[:4]
        assert args==[m.HANDLE,1,step,1]
        assert num(stop,stop.regs.ra)==HEADER_RETURN
        history=list(stop.history.bbl_addrs)[before:]
        assert all(pc in history for pc in (0x80081C98,PARSER,0x800840FC))
        assert not any(pc in history for pc in (m.BURN_NAND,m.HOST_ACK,m.CARD_READ))
        fields={hex(off):u32(stop,m.HANDLE+off) for off in (0x1CC,0xBF4,0xC18)}
        fields['0xc14']=int.from_bytes(read_bytes(stop,m.HANDLE+0xC14,2),'little')
        assert fields['0x1cc']==0 and fields['0xbf4']==0x100000
        assert 1<<fields['0xc14']==step and fields['0xc18']==(initial_flags|flag)
        entry=dict(supplied_id_hex=supplied.hex(),stop_before=hex(stop.addr),
            return_address=hex(num(stop,stop.regs.ra)),arguments=[hex(x) for x in args],
            initial_c18=initial_flags,fields=fields,vex_events=len(history),events=list(events))
        if scenario is None:
            return entry
        return header_case(p,angr,stop,before,entry,dict(scenario=scenario,fourth=fourth))

    return m.replay_mode(p,angr,header,b'',native_open=True,on_native_open=after_id_request)


def header_case(p,angr,st,before,entry,case):
    step=int(entry['arguments'][2],16)
    scenario=case['scenario']
    redirect=scenario!='clear'
    location=0x123
    aligned=(location//step)*step
    first,second=bytearray(0x400),bytearray(0x400)
    struct.pack_into('<I',first,0x14,(0x80000000 if redirect else 0)|location)
    struct.pack_into('<I',first,0x200,0x11111111)
    struct.pack_into('<I',second,0x200,0x22222222)
    replies=[(6,0,1,0),(4,0,2,0)]
    if redirect:
        replies += [(6,aligned,1,0),(4,aligned,2,7 if scenario=='second-read-fails' else 0)]
    io,allocations,releases,branch=[],[],[],[]
    prefix_count=len(list(st.history.bbl_addrs))
    initial_sp=num(st,st.regs.sp)

    class Nand(angr.SimProcedure):
        def run(self):
            args=arguments(self.state)
            size=u32(self.state,num(self.state,self.state.regs.sp)+28)
            dev,handle,op,position,count,data,extra=args
            assert len(io)<len(replies)
            expected_op,expected_position,expected_count,status=replies[len(io)]
            assert (dev,handle,op,position,count)==(1,m.HANDLE,expected_op,expected_position,expected_count)
            assert num(self.state,self.state.regs.ra)==0x80053F0C
            row=dict(operation=op,position=position,count=count,status=status,data=hex(data),extra=hex(extra),extra_size=size)
            if op==6:
                assert data==0 and extra!=0 and size==16
                supplied=b'\xff'*16
                self.state.memory.store(extra,supplied,size=16)
            else:
                assert (data,extra,size)==(m.INSTALLED,0,0)
                supplied=bytes(first if len(io)==1 else second)
                if status==0:
                    self.state.memory.store(data,supplied,size=len(supplied))
            row['supplied_sha256']=sha256(supplied).hexdigest() if status==0 else None
            io.append(row)
            return status

    class Allocate(angr.SimProcedure):
        def run(self):
            assert arguments(self.state)[:5]==[0,0x400,0,0x80063A88,0x6CB]
            assert not allocations
            self.state.memory.store(m.INSTALLED,bytes(0x400),size=0x400)
            allocations.append(dict(size=0x400,address=hex(m.INSTALLED)))
            return m.INSTALLED

    class Release(angr.SimProcedure):
        def run(self):
            assert arguments(self.state)[:4]==[0,m.INSTALLED,0x80063A88,0x6E1]
            assert not releases
            releases.append(dict(address=hex(m.INSTALLED),native_return_address=hex(num(self.state,self.state.regs.ra))))
            return 0

    def observe_branch(state):
        word=num(state,state.regs.t0)
        branch.append(dict(pc='0x80055c28',word=hex(word),signed_nonnegative=word<0x80000000))

    p.hook(m.NAND_EX,Nand(num_args=0),replace=True)
    p.hook(0x8000BF28,Allocate(num_args=0))
    p.hook(0x8000C598,Release(num_args=0))
    st.inspect.b('instruction',when=angr.BP_BEFORE,instruction=0x80055C28,action=observe_branch)
    final=advance(p,st,HEADER_RETURN,angr,steps=1000)
    assert num(final,final.regs.sp)==initial_sp
    result=num(final,final.regs.v0)
    failed=scenario=='second-read-fails'
    assert result==(0 if failed else m.INSTALLED)
    assert len(io)==len(replies) and len(allocations)==1 and len(releases)==int(failed)
    assert branch==[dict(pc='0x80055c28',word=hex(struct.unpack_from('<I',first,0x14)[0]),signed_nonnegative=not redirect)]
    final_bytes=read_bytes(final,m.INSTALLED,0x400)
    assert final_bytes==bytes(second if redirect and not failed else first)
    history=list(final.history.bbl_addrs)[prefix_count:]
    assert all(address in history for address in (HEADER_ENTRY,0x80055B9C,0x80055A3C,m.NAND_WRAPPER))
    assert (0x80055C30 in history)==redirect
    assert m.BURN_NAND not in history and m.CARD_READ not in history
    assert u32(final,m.HANDLE+0xBF4)==entry['fields']['0xbf4']
    return dict(case=case,entry=entry,stop_before=hex(HEADER_RETURN),header_return=hex(result),branch=branch,
        read_location_input=location,derived_stride=step,aligned_redirect=aligned if redirect else None,
        io=io,allocations=allocations,modeled_releases=releases,
        resulting_synthetic_buffer_sha256=sha256(final_bytes).hexdigest(),prefix_vex_events=entry['vex_events'],
        additional_vex_events=len(history),total_vex_events=len(list(final.history.bbl_addrs)[before:]),
        native_header_word_200_consumer_executed=False)


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
    parser=parser_cases(load_project(elf),angr)
    entries=[native_open_case(load_project(elf),angr,header,fourth) for fourth in (0,1)]
    redirected=[native_open_case(load_project(elf),angr,header,fourth,scenario)
                for scenario,fourth in (('clear',0),('redirect',0),('redirect',1),('second-read-fails',0))]
    assert [r['vex_events'] for r in entries]==[321,324]
    assert [r['total_vex_events'] for r in redirected]==[353,369,372,378]
    return dict(schema_version=1,input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,
        engine=f'angr {angr.__version__} / original MIPS32 little-endian / VEX',
        scope='12 isolated parser controls, 2 separate native-open-to-header-entry controls, and 4 separate continuations through one boot-header redirect branch.',
        source=source,modeled_apis=dict(native_open=m.NATIVE_OPEN_MODELS,
            id_response={'0x80053124':'Supply status zero and eight synthetic ID bytes after the original request assertions.'},
            header_body={'0x80053124':'Supply FF spare bytes, synthetic header bytes or data-read failure 7; no device I/O.',
                '0x8000bf28':'Supply one zeroed 0x400-byte synthetic header allocation.',
                '0x8000c598':'Record a release request without actually freeing memory.'}),
        assumptions=[
            'Each case starts a fresh project and synthetic RAM state. The four continuations retain their own native-open state.',
            'Native-open cases stop at 0x80056644 before its body. Redirect cases stop at 0x80084114 before the caller reads header +0x200.',
            'Request position and count are ABI values. The observed boot-header helper passes literal count 2; the caller separately computes 0x400 >> 9. Physical NAND sector/page/block units and geometry remain unobserved.',
            'Flat ELF virtual addresses and synthetic pointers; KSEG aliases, TLB, caches, DMA and physical address equivalence are not modeled.',
            'Device ID f1 is only a static dispatch target; installed ID and device meaning are unknown. It is not identified with the separate FileX return value f1.',
            'Geometry routine source is inspected only, not executed by these cases. No flash write, camera boot, capture or physical lens operation.'],
        parser=parser,native_open_entries=entries,header_redirect=redirected)


def validate_report(report):
    if not __debug__:
        raise RuntimeError('validation requires assertions')
    digest=sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
    assert digest==REPORT_SHA256,'NAND header observations differ'


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
            json.dump(report,out,indent=2)
            out.write('\n')
    except FileExistsError:
        parser.error('output appeared while replaying')
    print('PASS original MIPS/VEX: 12 ID parser, 2 header-entry and 4 header-redirect controls')


if __name__=='__main__':
    main()
