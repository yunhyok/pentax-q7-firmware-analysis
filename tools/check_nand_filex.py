"""Replay Q7 explicit AppFb entry through the first unresolved NAND status; no camera access."""
from pathlib import Path
from hashlib import sha256
from types import ModuleType
from os.path import lexists
import argparse,json

SHA='8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b'
ELF_SHA256='a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796'
CONTEXT_SHA256='98d9cb23517be9e29a57ccd2e9eefb599ecc400fd30bda862013d318863fecc6'
NATIVE_SHA256='c4bdf7588c28e1baa2e7b0d3374e67e82b1d77f3c8e34f4ae7e6cb80f667b572'
STATIC_SHA256='3ed57512ae6bceb9604b69ca5f8caf7dd7fe98a8fe60029ff48a7a628e2cba34'
REPORT_SHA256='fddd47dea0a5cd639aa2bda20c137c47114c8851e8c8a5ff23a3440655375070'

def canonical(value):
 return sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()

def load_helper(tools_dir=None):
 if not __debug__:raise RuntimeError('replay requires assertions')
 path=(Path(tools_dir) if tools_dir is not None else Path(__file__).resolve().parent)/'check_nand_context.py'
 source=path.read_bytes()
 if sha256(source).hexdigest()!=CONTEXT_SHA256:raise ValueError('source pin mismatch: check_nand_context')
 helper=ModuleType('pinned_nand_context');helper.__file__=str(path)
 exec(compile(source,str(path),'exec',dont_inherit=True),helper.__dict__)
 return helper

def static_ranges(elf,mods,evidence):
 layout,_=mods['inspect_q7'].parse_elf(elf,0)
 for row in evidence['ranges']:
  va,size=int(row['address'],16),row['size']
  segment=next(s for s in layout['segments'] if s['type']==1 and s['virtual_address']<=va and va+size<=s['virtual_address']+s['file_size'])
  offset=segment['file_offset']+va-segment['virtual_address']
  assert sha256(elf[offset:offset+size]).hexdigest()==row['sha256'],'static source range differs'

def replay(firmware,elf):
 if not __debug__:raise RuntimeError('replay requires assertions')
 if sha256(firmware).hexdigest()!=SHA:raise ValueError('expected SHA-pinned Q7 firmware')
 elf_bytes=elf.read_bytes()
 if sha256(elf_bytes).hexdigest()!=ELF_SHA256:raise ValueError('expected SHA-pinned Q7 analysis ELF')
 dep=load_helper()
 evidence=json.loads((Path(__file__).resolve().parents[1]/'analysis/nand-filex-source.json').read_bytes())
 if canonical(evidence)!=STATIC_SHA256:raise ValueError('static evidence differs')
 # Serial replay: the existing helper replaces project modules with captured verified source.
 with dep.pinned_dependencies() as modules:
  source=dep.source_evidence(firmware,elf_bytes,modules)
  static_ranges(elf_bytes,modules,evidence)
  native=run_native(dep,elf)
 report=dict(schema_version=1,input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,source=source,native_trace=native,static_evidence=evidence)
 validate_report(report)
 return report

def validate_report(report):
 if not __debug__:raise RuntimeError('validation requires assertions')
 assert report['schema_version']==1 and report['input_sha256']==SHA and report['analysis_elf_sha256']==ELF_SHA256
 assert canonical(report['native_trace'])==NATIVE_SHA256,'native trace differs'
 assert canonical(report['static_evidence'])==STATIC_SHA256,'static evidence differs'
 assert canonical(report)==REPORT_SHA256,'complete report differs'

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument('firmware',type=Path);ap.add_argument('elf',type=Path);ap.add_argument('--output',type=Path,required=True)
 args=ap.parse_args()
 if not __debug__:ap.error('replay requires assertions')
 if lexists(args.output):ap.error('output must not exist')
 report=replay(args.firmware.read_bytes(),args.elf)
 validate_report(report)
 try:
  with args.output.open('x',encoding='utf-8',newline='\n') as stream:json.dump(report,stream,indent=2);stream.write('\n')
 except FileExistsError:ap.error('output appeared while replaying')
 print('PASS explicit AppFb arguments and unresolved NAND status boundary')

MUTEX,RECORD,HEADER,MEDIA,BUFFER=0x24600000,0x24601000,0x24602000,0x24700000,0x24701000
REGISTRY,ECC,CONTEXT=0x800631d0,0x80059a58,0x8008c14c
NAND=0x80053124
TEMP=0x24800000

def run_native(dep,elf):
 import angr;from angr import claripy
 from check_isp_registers import load_project,STACK_TOP,RETURN_PC
 from check_q7_portability import new_state,guard
 from check_burn_storage import arguments,num,u32,read_bytes
 p=load_project(elf);events=[];writes=[];reads=[];phase=['producer'];io=[];consumer_io=[];checkpoints=[];temporary_allocations=[];spare_ranges=[];supplied_status=[]
 def value(st,expr):return {'symbolic':True,'bits':expr.size()} if st.solver.symbolic(expr) else st.solver.eval(expr)
 def snapshot(st,name):
  checkpoints.append(dict(name=name,pc=hex(st.addr),raw_register_stack_words=[hex(x) for x in arguments(st)],return_address=hex(num(st,st.regs.ra)),vex_events=len(list(st.history.bbl_addrs)),registry_kind1=hex(u32(st,REGISTRY+4)),config_pointer=hex(u32(st,RECORD+0xc84)),header_220_symbolic=st.solver.symbolic(st.memory.load(HEADER+0x220,4,inspect=False)),record_c88=value(st,st.memory.load(RECORD+0xc88,1,inspect=False)),record_c8c=value(st,st.memory.load(RECORD+0xc8c,4,inspect=False)),tl_context=hex(u32(st,CONTEXT))))
 class Model(angr.SimProcedure):
  def run(self,*,address):
   st=self.state;a=arguments(st);ra=num(st,st.regs.ra);result=0
   if address==0x8000c2b4:
    size=a[1]*a[2];result={0x2c:MUTEX,0xc90:RECORD,0xc78:MEDIA,0x4000:BUFFER}[size]
    expected={0x2c:0x80056194,0xc90:0x80055fdc,0xc78:0x800e7dc8,0x4000:0x800e7dec}
    assert a[0]==0 and a[3]==0 and ra==expected[size]
    st.memory.store(result,bytes(size),size=size)
   elif address==0x8000bf28:
    if phase[0]=='producer':
     assert a[:5]==[0,0x400,0,0x80063a88,0x3e1] and ra==0x8005635c
     result=HEADER;st.memory.store(result,bytes(0x400),size=0x400)
    else:
     assert a[:5]==[0,0x400,0,0x80063a88,0x6cb] and ra==0x80056700 and not temporary_allocations
     result=TEMP;st.memory.store(result,claripy.BVS('unknown_temporary_allocation',0x400*8),size=0x400)
     temporary_allocations.append(dict(address=hex(result),size=0x400,return_address=hex(ra),initialized_by='independent symbolic allocation, not NAND response',arguments=[hex(x) for x in a[:5]]))
   elif address==0x800cdb00:assert a[:3]==[MUTEX,0x80063b60,1]
   elif address==0x800cbee4:assert a[:2]==[MUTEX,0xffffffff]
   elif address==0x800d193c:assert a[0]==MUTEX
   elif address==0x800cda5c:
    raise AssertionError('unexpected event address')
   elif address==EVENT_GET:
    assert a[:3]==[0x800eabc4,0x200,2] and a[4]==0xffffffff
    st.memory.store(a[3],(0x200).to_bytes(4,'little'),size=4)
   else:assert address==0x800a14f8
   events.append(dict(phase=phase[0],address=hex(address),return_address=hex(ra),arguments=[hex(x) for x in a],result=hex(result)))
   return result
 class Response(angr.SimProcedure):
  def run(self):
   st=self.state;a=arguments(st);extra_size=u32(st,num(st,st.regs.sp)+28)
   dev,handle,op,pos,count,data,extra=a
   assert phase[0]=='producer' and (dev,handle,pos)==(1,RECORD+8,0)
   if len(io)==0:
    assert op==2 and (count,extra,extra_size)==(0,0,0)
    st.memory.store(data,bytes.fromhex('ecdc000100000000'),size=8);supplied='synthetic ID ecdc000100000000, status0'
   elif len(io)==1:
    assert op==6 and (count,data,extra_size)==(1,0,16)
    st.memory.store(extra,b'\xff'*16,size=16);supplied='synthetic FF spare16,status0'
   else:
    assert len(io)==2 and op==4 and (count,data,extra,extra_size)==(2,HEADER,0,0)
    st.memory.store(HEADER,claripy.BVS('unknown_installed_header',0x400*8),size=0x400)
    st.memory.store(HEADER+0x14,bytes(4),size=4)
    supplied='symbolic header400 bytes except +14=0 nonredirect control; status0; no concrete +220/398/3a8/3ac'
   io.append(dict(arguments=[hex(x) for x in a+[extra_size]],supplied=supplied))
   return 0
 EVENT_GET=0x800cc3b4
 for address in (0x8000c2b4,0x8000bf28,0x800cdb00,0x800cbee4,0x800d193c,0x800a14f8,EVENT_GET):p.hook(address,Model(num_args=0,address=address))
 p.hook(NAND,Response(num_args=0))
 st=new_state(p,angr);st.memory.store(STACK_TOP-0x2000,bytes(0x2000),inspect=False)
 image=tuple((s.min_addr,s.max_addr+1) for s in p.loader.main_object.segments)
 ram=((STACK_TOP-0x2000,STACK_TOP-0x400),(MUTEX,MUTEX+0x2c),(RECORD,RECORD+0xc90),(HEADER,HEADER+0x400),(TEMP,TEMP+0x400),(MEDIA,MEDIA+0xc78),(BUFFER,BUFFER+0x4000),(REGISTRY,REGISTRY+12),(ECC,ECC+2),(0x8008c2dc,0x8008c2dd),(0x8008c2e0,0x8008c2f8))
 guard(st,angr,ram,(*image,(0x81547f10,0x81547f14)))
 def watch_read(s):
  a=s.inspect.attrs;addr=num(s,a.mem_read_address)
  if HEADER<=addr<HEADER+0x400 or TEMP<=addr<TEMP+0x400 or RECORD<=addr<RECORD+0xc90 or any(lo<=addr<hi for lo,hi in spare_ranges) or addr in (REGISTRY,REGISTRY+4,CONTEXT):
   reads.append(dict(phase=phase[0],pc=hex(num(s,s.scratch.ins_addr)),address=hex(addr),size=num(s,a.mem_read_length),value=value(s,a.mem_read_expr)))
 def watch_write(s):
  a=s.inspect.attrs;addr=num(s,a.mem_write_address)
  if addr in (REGISTRY+4,RECORD+0xc84,RECORD+0xc88,RECORD+0xc8c,MEDIA+0x1d4,MEDIA+0x1c4,MEDIA+0x1c8,MEDIA+0xbf4,MEDIA+0xc10,MEDIA+0xc14,MEDIA+0xc18,CONTEXT):
   writes.append(dict(phase=phase[0],pc=hex(num(s,s.scratch.ins_addr)),address=hex(addr),size=num(s,a.mem_write_length),value=value(s,a.mem_write_expr)))
 st.inspect.b('mem_read',when=angr.BP_AFTER,action=watch_read)
 st.inspect.b('mem_write',when=angr.BP_BEFORE,action=watch_write)
 def walk(state,target,steps=20000):
  sim=p.factory.simgr(state,save_unconstrained=True);sim.explore(find=target,n=steps)
  assert len(sim.found)==1 and not(sim.active or sim.errored or sim.unconstrained or sim.deadended),(sim,sim.errored)
  return sim.found[0]
 st.regs.pc,st.regs.ra,st.regs.a0=0x800f4de8,RETURN_PC,8
 produced=walk(st,RETURN_PC)
 assert len(io)==3 and num(produced,produced.regs.v0)==1 and num(produced,produced.regs.sp)==STACK_TOP
 assert produced.solver.symbolic(produced.memory.load(HEADER+0x220,4,inspect=False))
 assert produced.solver.symbolic(produced.memory.load(HEADER+0x398,1,inspect=False))
 snapshot(produced,'producer returns1 with unresolved header fields')
 phase[0]='explicit AppFbLoader entry';p.unhook(NAND)
 consumer=produced.copy();consumer.regs.pc,consumer.regs.ra,consumer.regs.a0=0x800e7d64,RETURN_PC,1
 opened=walk(consumer,0x80067700)
 assert arguments(opened)==[MEDIA,0x800ebd58,0x8006444c,2,BUFFER,0x4000,1]
 snapshot(opened,'original AppFbLoader built exact FileX arguments; no arg override')
 checkpoints[-1]['filex_arguments']=[hex(x) for x in arguments(opened)]
 first_missing=walk(opened,0x80066a68)
 snapshot(first_missing,'first unresolved consumer global: _fx_system_media_opened_ptr at81547f10; not read')
 first_missing.memory.store(0x81547f10,bytes(4),size=4,inspect=False)
 events.append(dict(phase=phase[0],address='0x81547f10',model='explicit empty FileX open-list control',result=0))
 stopped=walk(first_missing,NAND)
 assert arguments(stopped)[:5]==[1,MEDIA,2,0,0]
 assert u32(stopped,num(stopped,stopped.regs.sp)+28)==16
 assert u32(stopped,MEDIA+0x1d4)==1 and u32(stopped,MEDIA+0x1c4)==2
 assert u32(stopped,CONTEXT)==0 and produced.solver.constraints==stopped.solver.constraints
 assert not [r for r in reads if r['phase']!='producer' and HEADER<=int(r['address'],16)<HEADER+0x400]
 assert not [r for r in reads if r['phase']!='producer' and RECORD<=int(r['address'],16)<RECORD+0xc90]
 assert u32(stopped,REGISTRY+4)==RECORD and u32(stopped,RECORD+0xc84)==HEADER
 for address,size in ((HEADER+0x220,4),(HEADER+0x398,1),(RECORD+0xc88,1),(RECORD+0xc8c,4)):
  assert stopped.solver.symbolic(stopped.memory.load(address,size,inspect=False))
 snapshot(stopped,'stop before downstream ID op2; no consumer NAND response')
 class Downstream(angr.SimProcedure):
  def run(self):
   st=self.state;a=arguments(st);size=u32(st,num(st,st.regs.sp)+28)
   assert a[:2]==[1,MEDIA] and num(st,st.regs.ra)==0x80053f0c
   if not consumer_io:
    assert a[2:5]==[2,0,0] and a[6]==0 and size==16
    st.memory.store(a[5],bytes.fromhex('ecdc000100000000'),size=8)
    result=0;supplied='reused synthetic ID ecdc000100000000, status0'
   else:
    assert len(consumer_io)==1 and a[2:6]==[6,0,1,0] and size==16
    spare_ranges.append((a[6],a[6]+16))
    st.memory.store(a[6],claripy.BVS('unknown_downstream_spare',128),size=16)
    result=claripy.BVS('unknown_downstream_op6_status',32);supplied_status.append(result)
    supplied='independent symbolic spare16 and symbolic 32-bit status; no success assumption'
   consumer_io.append(dict(arguments=[hex(x) for x in a+[size]],return_address=hex(num(st,st.regs.ra)),supplied=supplied,status=0 if isinstance(result,int) else dict(symbolic=True,bits=32)))
   return result
 print('Checkpoint stage23 retained',flush=True)
 phase[0]='downstream ID control then unknown op6'
 p.hook(NAND,Downstream(num_args=0))
 entry=walk(stopped,0x80056644)
 assert arguments(entry)[:4]==[MEDIA,1,256,1] and num(entry,entry.regs.ra)==0x80084114
 print('Checkpoint header entry',flush=True)
 geometry=dict(media_capacity_bf4=u32(entry,MEDIA+0xbf4),media_flags_c18=hex(u32(entry,MEDIA+0xc18)),media_shift_c14=int.from_bytes(read_bytes(entry,MEDIA+0xc14,2),'little'),header_arguments=[hex(x) for x in arguments(entry)[:4]],return_address=hex(num(entry,entry.regs.ra)))
 snapshot(entry,'after reused ID: original FcuMediaInfoGetHeader entry')
 op6=walk(entry,NAND)
 assert len(consumer_io)==1 and arguments(op6)[0:6]==[1,MEDIA,6,0,1,0] and u32(op6,num(op6,op6.regs.sp)+28)==16
 print('Checkpoint op6 ABI',flush=True)
 snapshot(op6,'independent temporary allocation; first op6 ABI before response')
 final=walk(op6,0x80055aac)
 print('Checkpoint pre-branch reached',flush=True)
 status=final.regs.v0
 assert final.solver.symbolic(status)
 assert status.op=='BVS' and status.size()==32 and len(status.variables)==1
 assert status.variables==supplied_status[0].variables and not final.solver.constraints
 print('Checkpoint unresolved status BVS32 with no constraints',flush=True)
 assert final.solver.constraints==produced.solver.constraints
 assert len(consumer_io)==2 and len(temporary_allocations)==1 and u32(final,CONTEXT)==0
 assert u32(final,REGISTRY+4)==RECORD and u32(final,RECORD+0xc84)==HEADER
 assert not [r for r in reads if r['phase']!='producer' and (HEADER<=int(r['address'],16)<HEADER+0x400 or TEMP<=int(r['address'],16)<TEMP+0x400 or RECORD<=int(r['address'],16)<RECORD+0xc90 or any(lo<=int(r['address'],16)<hi for lo,hi in spare_ranges))]
 original=final.memory.load(HEADER,0x400,inspect=False);temporary=final.memory.load(TEMP,0x400,inspect=False)
 assert original.symbolic and temporary.symbolic and original.variables.isdisjoint(temporary.variables)
 spare=final.memory.load(spare_ranges[0][0],16,inspect=False)
 variable_sets=[original.variables,temporary.variables,spare.variables,status.variables]
 assert all(a.isdisjoint(b) for i,a in enumerate(variable_sets) for b in variable_sets[i+1:])
 history=list(final.history.bbl_addrs)
 assert all(pc not in history for pc in (0x80084114,0x80084bc0,0x80055534,0x80084558))
 assert len([e for e in events if e.get('address')=='0x800cbee4' and e.get('return_address')=='0x80056698'])==1
 assert u32(final,MEDIA+0xc10)==0 and not [w for w in writes if w['address']==hex(MEDIA+0xc10) and w['pc']=='0x80084128']
 print('Checkpoint memory invariants',flush=True)
 snapshot(final,'stop before first unresolved status branch 80055aac')
 out=dict(input_sha256=dep.SHA,analysis_elf_sha256=dep.ELF_SHA256,engine=f'angr {angr.__version__}/VEX',prefix_stage23_script_sha256='aebd19b200b66fbfede3887fd08053b5f4c2ff584035fd1f0706e5ae2605a415',source_loader_sha256=CONTEXT_SHA256,scope='Continuation of explicit cross-entry model. Stop before first new unknown status branch; no later path assumptions.',producer_io=io,consumer_io=consumer_io,api_models=events,temporary_allocations=temporary_allocations,geometry_from_synthetic_id=geometry,checkpoints=checkpoints,reads=reads,writes=writes,final=dict(pc=hex(final.addr),branch='bnez v0,0x80055b08',status_symbolic=True,status_ast_op='BVS',status_bits=32,status_matches_supplied_symbol=True,path_constraints_count=0,independent_variable_sets=True,admissible_examples_by_construction=[0,1],sat_queries_run=False,sat_query_limit='Earlier diagnostic process exited -1073741819 at first satisfiable query; accepted run uses exact unconstrained BVS contract and makes no solver SAT claim',branch_executed=False,delay_slot_executed=False,delay_slot='move a2,s0 @80055ab0',fallthrough='80055ab4: lbu v1,spare+5',target='80055b08: diagnostic then failure return',temporary_header=hex(TEMP),registry_header=hex(HEADER),headers_distinct_addresses=True,headers_disjoint_symbolic_variables=True,temporary_header_is_allocation_not_media_data=True,spare_address=hex(spare_ranges[0][0]),spare_byte5_load_executed=False,new_op4_requested=False,temp_200_to_media_c10_executed=False,zone_lookup_executed=False,partition_index1_executed=False,header220_concrete_supplied=False,positive_tl_handle_supplied=False,tl_context_zero=True,branch_constraints_added=0),limits=['Stage23 explicit AppFb restart and allocation/mutex/event/opened-list0 controls retained.','New ID/status0 explicitly reused synthetic control.','New op6 spare and status unknown; no assumption on status success, spare+5, temporary header+14 or+200.','Temporary allocation is symbolic and independent of registered header; op4 not reached.','Subsequent copy,zone and partition-index contracts are static only. No camera/boot/MMIO success.'])
 return out

if __name__=='__main__':main()
