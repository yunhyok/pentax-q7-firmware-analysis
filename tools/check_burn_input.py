"""Offline replay of E01 card read verification and section-protection predicates.

FileX, allocation/cache and asynchronous MD5 results are modeled. No storage
write routine or camera connection is used.
"""
import argparse
import hashlib
import io
import json
import struct
from pathlib import Path
from inspect_q7 import parse_elf
from q7_symbols import SHA

RETURN,STACK,HANDLE,DEST,TEMP,SECTION,HEADER=0x0BADF000,0x70008000,0x10000000,0x10002000,0x10003000,0x10004000,0x10005000
OLD_HEADER,MAP=0x10007000,0x10008000
PRIMARY=0x10010000
DATA=bytes(range(64))


def cases():
    # kind, delivered bytes, status; hash results are asynchronous worker outputs.
    a=DATA;b=bytes([255])+a[1:]
    for name,flag,reads,seeks,hashes,result in (
        ('double-read-equal',0,[a,a],[0],[],1),
        ('mismatch-retry-success',0,[a,b,a,a],[0,0,0],[],1),
        ('mismatch-both-attempts',0,[a,b,a,b],[0,0,0,0],[],0),
        ('different-actual-lengths',0,[a,a[:-1]],[0],[],0),
        ('equal-short-reads',0,[a[:8],a[:8]],[0],[],1),
        ('equal-empty-success-reads',0,[b'',b''],[0],[],1),
        ('first-read-error',0,[(b'',1)],[],[],0),
        ('second-read-error',0,[a,(b'',1)],[0],[],0),
        ('first-rewind-error',0,[a],[1],[],0),
        ('mismatch-rewind-error',0,[a,b],[0,1],[],0),
        ('hash-worker-success',1,[a+bytes(16)],[],[1],1),
        ('hash-worker-retry-success',1,[a+bytes(16),a+bytes(16)],[0],[0,1],1),
        ('hash-worker-fails-twice',1,[a+bytes(16),a+bytes(16)],[0,0],[0,0],0),
        ('hash-worker-rewind-error',1,[a+bytes(16)],[1],[0],0),
    ):
        yield name,flag,[(r,0) if isinstance(r,bytes) else r for r in reads],seeks,hashes,result


def replay(firmware):
    if not __debug__: raise RuntimeError('Replay requires assertions')
    if hashlib.sha256(firmware).hexdigest()!=SHA: raise ValueError('expected SHA-pinned Q7 v1.01')
    boot,_=parse_elf(firmware,0x200)
    import angr
    project=angr.Project(io.BytesIO(firmware[0x200:boot['referenced_end']]),auto_load_libs=False)
    def num(st,value):
        assert not value.symbolic
        return st.solver.eval(value)
    def u32(st,addr): return num(st,st.memory.load(addr,4,endness='Iend_LE'))
    class Model(angr.SimProcedure):
        def run(self,a0,a1,a2,a3,kind=None):
            st=self.state;events=st.globals['events']
            if kind=='alloc':
                assert num(st,a1)==64
                st.memory.store(TEMP,bytes(64));return TEMP
            if kind=='read':
                index=st.globals['read_index'];planned=st.globals['reads']
                assert index<len(planned)
                content,status=planned[index];st.globals['read_index']=index+1
                address,requested=num(st,a1),num(st,a2)
                assert address in (DEST,TEMP)
                assert requested==(80 if st.globals['flag'] else 64)
                assert len(content)<=requested
                if content: st.memory.store(address,content)
                st.memory.store(num(st,a3),struct.pack('<I',len(content)))
                events.append(dict(kind='read',destination='primary' if address==DEST else 'comparison',requested=requested,actual=len(content),status=status))
                return status
            if kind=='seek':
                index=st.globals['seek_index'];planned=st.globals['seeks'];assert index<len(planned)
                st.globals['seek_index']=index+1
                low,high,option=num(st,a2),num(st,a3),u32(st,num(st,st.regs.sp)+16)
                assert high==0 and option==3
                events.append(dict(kind='relative_seek',distance=low,high=high,option=option,status=planned[index]))
                return planned[index]
            if kind=='hash_init': events.append(dict(kind=kind));return 0
            if kind=='hash_update':
                assert num(st,a0)==HANDLE and num(st,a1)==DEST and num(st,a2)==64
                events.append(dict(kind=kind,bytes=num(st,a2)));return 0
            if kind=='hash_finalize':
                assert num(st,a0)==HANDLE and num(st,a1)==DEST+64
                index=st.globals['hash_index'];planned=st.globals['hashes'];assert index<len(planned)
                st.globals['hash_index']=index+1
                events.append(dict(kind=kind,digest_offset=64,modeled_result=planned[index]));return planned[index]
            if kind=='payload':
                assert num(st,a0)==0x20000 and num(st,a1)==PRIMARY
                st.memory.store(PRIMARY,firmware[0x1000C0:0x1200C0])
                events.append(dict(kind=kind,original_file_offset='0x1000c0',bytes=0x20000));return 1
            if kind=='media_header':
                events.append(dict(kind=kind,selector=num(st,a3)));return OLD_HEADER
            if kind=='zones':
                st.memory.store(num(st,a2),struct.pack('<I',0x40000))
                st.memory.store(num(st,a3),struct.pack('<I',1))
                for arg in (16,20): st.memory.store(u32(st,num(st,st.regs.sp)+arg),struct.pack('<I',256))
                events.append(dict(kind=kind,total_sectors=0x40000,zone_blocks=256));return 0
            return 0
    hooks={0x80034720:'alloc',0x80048CF8:'cache',0x80034D98:'free',0x8004717C:'log',
           0x800632F4:'read',0x800622E0:'seek',0x8001BA40:'hash_init',0x8001BA74:'hash_update',0x8001BAAC:'hash_finalize',
           0x8001A444:'header diagnostic output'}
    for address,kind in hooks.items(): project.hook(address,Model(kind=kind))
    def state(pc,args=()):
        st=project.factory.blank_state(addr=pc,add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        st.regs.sp=STACK;st.regs.ra=RETURN
        st.memory.store(STACK-0x2000,bytes(0x3000));st.memory.store(HANDLE,bytes(0x9000))
        for i,arg in enumerate(args): setattr(st.regs,f'a{i}',arg)
        st.memory.store(0x800A7770,struct.pack('<I',HANDLE));st.memory.store(0x800C7438,struct.pack('<I',0x10006000))
        st.globals['events']=[];return st
    def run(st):
        sim=project.factory.simgr(st);sim.explore(find=RETURN,n=4096)
        assert len(sim.found)==1 and not sim.active and not sim.errored,sim
        return sim.found[0]
    cards=[]
    for name,flag,reads,seeks,hashes,expected in cases():
        st=state(0x80019014,[64,DEST]);st.memory.store(HANDLE+0x1278,bytes([flag]))
        for key,val in dict(flag=flag,reads=reads,seeks=seeks,hashes=hashes,read_index=0,seek_index=0,hash_index=0).items(): st.globals[key]=val
        st=run(st);actual=num(st,st.regs.v0);assert actual==expected,(name,actual)
        assert (st.globals['read_index'],st.globals['seek_index'],st.globals['hash_index'])==(len(reads),len(seeks),len(hashes))
        cards.append(dict(name=name,hash_flag=flag,result=actual,events=st.globals['events']))
    protected=[]
    for kind in (0,1,2,3,4,5,6):
        for mode in (0,1):
            for current_protect in (0,1):
                for length,payload in ((0,0),(1,0),(1,1)):
                    expected=(mode==1 and current_protect==1) if kind==3 else ((mode==1 and payload==0) if kind==6 else (length!=0 and payload==0))
                    st=state(0x8001A2A4,[kind,SECTION,HEADER]);st.memory.store(SECTION,struct.pack('<3I',123,length,payload));st.memory.store(HEADER+0x234,bytes([mode]));st.memory.store(HANDLE+0x1268,bytes([current_protect]))
                    st=run(st);actual=num(st,st.regs.v0);assert actual==expected
                    protected.append(dict(section=kind,header_mode=mode,handle_protect=current_protect,span=length,payload=payload,result=actual))
    pointers=[]
    for kind in range(8):
        st=run(state(0x8001A6EC,[HEADER,kind]));offset=num(st,st.regs.v0)-HEADER
        assert offset==(0x3B0 if kind==0 else 0x214+kind*0x24)
        pointers.append(dict(section=kind,header_offset=hex(offset)))
    ready=run(state(0x80019390))
    assert num(ready,ready.regs.v0)==1
    maps=[]
    old=bytearray(firmware[0x1000C0:0x1008C0])
    # shortcut: synthetic installed-media geometry; replace with a captured
    # existing NAND header before making device-specific layout predictions.
    layout=[(0,0),(0,0xA00),(0xA00,0x13600),(0x14000,0x6000),
            (0x1A000,0x1000),(0x1B000,0xD000),(0x28000,0x18000)]
    for kind,(start,span) in enumerate(layout):
        offset=0x3B0 if kind==0 else 0x214+kind*0x24
        old[offset:offset+0x24]=struct.pack('<9I',start,span,0,0,0,0,0,0,0)
    for name,total,protect,change,expected in (
        ('compatible-existing-map',0x40000,1,None,0),
        ('resource-B-size-mismatch',0x40000,1,'B',3),
        ('protected-code-and-A-span-mismatch',0x40000,1,'A',3),
        ('unprotected-code-and-A-span-mismatch',0x40000,0,'A',0),
        ('protected-section3-start-mismatch',0x40000,1,'section3',3),
        ('unsupported-user-area-mode',0x40000,1,'mode',3),
        ('insufficient-sectors',0x20000,0,None,4),
        ('unknown-media-size',0xFFFFFFFF,0,None,1),
    ):
        existing=bytearray(old);incoming=bytearray(firmware[0x1000C0:0x1008C0])
        if change=='B': struct.pack_into('<I',existing,0x218,0x1001)
        if change=='A': struct.pack_into('<I',existing,0x260,0x13700)
        if change=='section3': struct.pack_into('<I',existing,0x280,0x14100)
        if change=='mode': struct.pack_into('<I',incoming,0x22C,1)
        st=state(0x8001A710,[HANDLE,MAP,HEADER,OLD_HEADER]);st.memory.store(HEADER,incoming);st.memory.store(OLD_HEADER,existing)
        for off,val in ((0x138,512),(0x1238,256),(0x123C,total)): st.memory.store(HANDLE+off,struct.pack('<I',val))
        st.memory.store(HANDLE+0x1268,bytes([protect]));st.memory.store(STACK+16,bytes(4))
        st=run(st);actual=num(st,st.regs.v0);assert actual==expected,(name,actual)
        out=[]
        if actual==0:
            for kind in range(7):
                addr=MAP+kind*0x24
                start,span,payload=[u32(st,addr+i) for i in (0,4,8)]
                protection=num(st,st.memory.load(addr+0x21,1))
                assert (start,span)==layout[kind]
                out.append(dict(section=kind,start_sector=start,span_sectors=span,file_sectors=payload,protected=protection))
        maps.append(dict(name=name,total_sectors=total,sectors_per_block=256,handle_protect=protect,result=actual,output_sections=out))
    prefix_hooks={0x80019014:'payload',0x8008495C:'media_header',0x80083744:'zones'}
    for address,kind in prefix_hooks.items(): project.hook(address,Model(kind=kind))
    st=state(0x80012654,[HANDLE,0x800A74DC]);st.memory.store(OLD_HEADER,old)
    for off,val in ((0x138,512),(0x1238,256),(0x123C,0x40000),(0x1248,0x20000),(0x124C,PRIMARY),(0x126C,1)):
        st.memory.store(HANDLE+off,struct.pack('<I',val))
    st.memory.store(HANDLE+0x1268,b'\x01')
    sim=project.factory.simgr(st);sim.explore(find=0x80012FF0,avoid=RETURN,n=4096)
    assert len(sim.found)==1 and not sim.active and not sim.errored and not sim.avoid,sim
    st=sim.found[0];assert num(st,st.regs.v0)==0
    actual_map=num(st,st.regs.sp)+0x28
    for kind,(start,span) in enumerate(layout):
        assert (u32(st,actual_map+0x24*kind),u32(st,actual_map+0x24*kind+4))==(start,span)
    prefix=dict(entry='0x80012654',stop='0x80012ff0',map_return=0,events=st.globals['events'],
                additional_modeled_functions={hex(k):v for k,v in prefix_hooks.items()},
                scope='Original BurnNand prologue, real original payload header, native BurnGetSectionsMap and protection helpers. Stop immediately after map return, before flash operations.')
    return dict(input_sha256=SHA,boot_elf_sha256=boot['sha256_referenced_bytes'],engine=f'angr {angr.__version__} / VEX',
                callback=dict(table='0x800a74dc',read='0x80019014',ready='0x80019390',ready_return=1),
                card_cases=cards,protection_cases=protected,section_pointer_cases=pointers,section_map_cases=maps,burn_nand_prefix=prefix,
                modeled_functions={hex(k):v for k,v in hooks.items()},
                limits=['Synthetic FileX status and actual-count results; no physical SD/NAND access.',
                        'MD5 worker outcomes are modeled. These cases prove callback handling, not cryptographic digest computation.',
                        'Two equal short or zero-length successful reads return 1 in this callback alone. This is not proof that a truncated update can pass later stages.',
                        'Protection fields retain numeric section IDs until caller/header semantics are separately established. Pointer helper index 7 computes an address but does not prove a valid eighth section.',
                        'Map cases use the original incoming boot header with synthetic installed-media header and NAND geometry, not a camera dump.',
                        'The BurnNand prefix models its card read with original input bytes and existing-media reads/geometry; no storage operation or full loader loop was executed.'])


def validate_report(report):
    """Check fixture results and modeled I/O contracts without the firmware."""
    assert report['input_sha256']==SHA
    assert report['engine'].startswith('angr ') and report['engine'].endswith(' / VEX')
    assert report['callback']==dict(table='0x800a74dc',read='0x80019014',ready='0x80019390',ready_return=1)
    for actual,fixture in zip(report['card_cases'],cases(),strict=True):
        name,flag,reads,seeks,hashes,result=fixture
        assert (actual['name'],actual['hash_flag'],actual['result'])==(name,flag,result)
        events=actual['events']
        observed=[e for e in events if e['kind']=='read']
        expected=[dict(kind='read',destination='primary' if flag or i%2==0 else 'comparison',
                       requested=80 if flag else 64,actual=len(data),status=status)
                  for i,(data,status) in enumerate(reads)]
        assert observed==expected
        assert [e['status'] for e in events if e['kind']=='relative_seek']==seeks
        assert all(e['high']==0 and e['option']==3 for e in events if e['kind']=='relative_seek')
        assert [e['modeled_result'] for e in events if e['kind']=='hash_finalize']==hashes
        assert sum(e['kind']=='hash_init' for e in events)==len(hashes)
        assert [e for e in events if e['kind']=='hash_update']==[dict(kind='hash_update',bytes=64)]*len(hashes)
    assert len(report['protection_cases'])==84
    assert [(c['section'],c['header_mode'],c['handle_protect'],c['span'],c['payload']) for c in report['protection_cases']]==[
        (kind,mode,protect,span,payload) for kind in range(7) for mode in (0,1) for protect in (0,1) for span,payload in ((0,0),(1,0),(1,1))]
    for c in report['protection_cases']:
        kind,mode,protect,span,payload=[c[k] for k in ('section','header_mode','handle_protect','span','payload')]
        expected=(mode==1 and protect==1) if kind==3 else ((mode==1 and payload==0) if kind==6 else (span!=0 and payload==0))
        assert c['result']==expected
    assert report['section_pointer_cases']==[dict(section=i,header_offset=hex(0x3b0 if i==0 else 0x214+i*0x24)) for i in range(8)]
    assert [c['result'] for c in report['section_map_cases']]==[0,3,3,0,3,3,4,1]
    for c in report['section_map_cases']:
        if c['result']!=0: assert not c['output_sections'];continue
        assert [s['file_sectors'] for s in c['output_sections']]==[0,2437,31832,0,0,0,0]
        assert [s['protected'] for s in c['output_sections']]==[0,0,0,c['handle_protect'],1,1,1]
        assert [(s['section'],s['start_sector'],s['span_sectors']) for s in c['output_sections']]==[
            (0,0,0),(1,0,0xa00),(2,0xa00,0x13600),(3,0x14000,0x6000),
            (4,0x1a000,0x1000),(5,0x1b000,0xd000),(6,0x28000,0x18000)]
    prefix=report['burn_nand_prefix']
    assert (prefix['entry'],prefix['stop'],prefix['map_return'])==('0x80012654','0x80012ff0',0)
    assert prefix['additional_modeled_functions']=={'0x80019014':'payload','0x8008495c':'media_header','0x80083744':'zones'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--output',required=True,type=Path);a=p.parse_args()
    if a.output.exists(): p.error('output must not exist')
    result=replay(a.firmware.read_bytes())
    validate_report(result)
    with a.output.open('x',encoding='utf-8') as f: f.write(json.dumps(result,indent=2)+'\n')
    print(f'{len(result["card_cases"])} card, {len(result["protection_cases"])} protection, {len(result["section_pointer_cases"])} pointer and {len(result["section_map_cases"])} map cases PASS')


if __name__=='__main__': main()
