"""Reproduce Q7 MAIN update file staging, header dispatch and wrapper returns offline."""
import argparse
from pathlib import Path
from os.path import lexists
import json
import struct
import hashlib
from check_isp_registers import load_project,STACK_TOP,ELF_SHA256
from check_q7_portability import new_state,guard,execute,value
from check_colorspace_ui import put,get,concrete
from q7_symbols import SHA

BUFFER,MEDIA,FILE,HANDLE=0x24000000,0x24010000,0x24020000,0x24030000
BRIDGE_APIS={0x8000c2b4:'calloc',0x8000bf28:'alloc',0x8000c598:'free',0x800a14f8:'log',0x80067700:'media_open',0x8006e984:'first',0x800731cc:'next',0x80074334:'file_open',0x8007d19c:'seek',0x80071a10:'read',0x8007c258:'file_close',0x80077e74:'media_close',0x805dc7f4:'led_init',0x805dc6b4:'led_status',0x805e5374:'burn',0x805e59b8:'reboot',0x800ec08c:'set_param',0x80125f14:'lock',0x80125f98:'unlock',0x801260b8:'thread'}

def bridge_case(elf, header, opts):
 import angr
 p=load_project(elf);events=[];observations=[];position=0
 def cstr(st,a):
  out=bytearray()
  for i in range(128):
   b=value(st,a+i,1)
   if b==b'\0':return out.decode()
   out+=b
  raise ValueError('unterminated string')
 class Model(angr.SimProcedure):
  def run(self,*,api):
   nonlocal position
   st=self.state;a=[concrete(st,getattr(st.regs,f'a{i}')) for i in range(4)];kind=BRIDGE_APIS[api];result=0
   ev=dict(api=hex(api),kind=kind,ra=hex(concrete(st,st.regs.ra)))
   if kind=='calloc':
    size=a[1]*a[2];result={0x2000:BUFFER,0xc78:MEDIA,0xd40:HANDLE}[size]
    st.memory.store(result,bytes(size),size=size);ev.update(size=size,pointer=hex(result))
   elif kind=='alloc':
    assert a[1]==0x1f8;result=FILE;st.memory.store(FILE,bytes(0x1f8),size=0x1f8)
   elif kind=='free':ev['pointer']=hex(a[1]);result=1
   elif kind=='media_open':
    ev.update(media=hex(a[0]),driver=hex(a[2]),info=hex(a[3]),buffer=hex(get(st,concrete(st,st.regs.sp)+16)))
    result=opts.get('media_open',0)
   elif kind=='first':
    data=b'upg_file.elf\0';st.memory.store(a[1],data,size=len(data));result=opts.get('first',0)
   elif kind=='next':result=1
   elif kind=='file_open':ev.update(path=cstr(st,a[2]),mode=a[3]);result=opts.get('file_open',0)
   elif kind=='seek':
    assert a[0]==FILE and a[2:]==[0x100000,0];position=a[2];ev['offset']=position;result=opts.get('seek',0)
   elif kind=='read':
    assert a[0]==FILE and a[3]==0 and a[2] in (64,128)
    count=a[2];data=header[position-0x100000:position-0x100000+count];assert len(data)==count
    st.memory.store(a[1],data,size=count);ev.update(offset=position,count=count,sha256=hashlib.sha256(data).hexdigest());position+=count
    result=opts.get('read' if count==64 else 'read_extended',0)
   elif kind in ('file_close','media_close'):result=opts.get(kind,0)
   elif kind=='burn':
    assert value(st,concrete(st,st.regs.s1),0xc0)==header
    ev.update(arguments=[hex(v) for v in a[:3]],callback=hex(get(st,HANDLE+0xca4)),device=hex(get(st,HANDLE+0xca8)),hash_flag=get(st,HANDLE+0xcc8,1),kind_id=get(st,HANDLE+0xcb4),header_sha256=hashlib.sha256(value(st,concrete(st,st.regs.s1),0xc0)).hexdigest())
    result=opts.get('burn',0)
   elif kind=='reboot':ev['header_reboot_field']=get(st,a[0]+12)
   elif kind=='led_status':ev['status']=a[0]
   elif kind=='set_param':ev['args']=a[:2]
   elif kind in ('lock','unlock'):ev['args']=a[:2] if kind=='lock' else a[:1]
   elif kind=='thread':ev['args']=a+[get(st,concrete(st,st.regs.sp)+i) for i in (16,20,24)];result=opts.get('thread',1)
   events.append(dict(ev,result=result));return result
 for api in BRIDGE_APIS:p.hook(api,Model(num_args=0,api=api))
 st=new_state(p,angr)
 for a,n in [(BUFFER,0x2000),(MEDIA,0xc78),(FILE,0x1f8),(HANDLE,0xd40),(0x805e885c,12),(0x815eddd0,4),(0x807f2520,12)]:st.memory.store(a,bytes(n))
 put(st,0x807f2524,0x24040000)
 globals_ram=((0x805e885c,0x805e8868),(0x815eddd0,0x815eddd4),(0x807f2520,0x807f252c))
 regions=((BUFFER,BUFFER+0x2000),(MEDIA,MEDIA+0xc78),(FILE,FILE+0x1f8),(HANDLE,HANDLE+0xd40),*globals_ram)
 image=tuple((s.min_addr,s.max_addr+1) for s in p.loader.main_object.segments)
 guard(st,angr,regions,image)
 entry=0x807f2270 if opts.get('outer') else 0x8024e840
 args=(opts.get('sync',1),) if opts.get('outer') else (0xfe,)
 def watch(st):
  observations.append(dict(pc=hex(st.addr),return_value=concrete(st,st.regs.v0)))
 st.inspect.b('instruction',when=angr.BP_BEFORE,instruction=0x805e5bd4,action=watch)
 st.inspect.b('instruction',when=angr.BP_BEFORE,instruction=0x807f1f88,action=watch)
 st=execute(p,st,entry,*args,steps=12000)
 return dict(options=opts,result=concrete(st,st.regs.v0),updating=get(st,0x807f2520,1),events=events,observations=observations)


STAGING_BUFFER=0x25000000
INPUT=b'Q7 staging fixture\0'+bytes(range(77))
assert len(INPUT)==96
STAGING_APIS={0x80260e1c:'size',0x801049c4:'board',0x800ec0b0:'set_long',0x800ec100:'get_param',0x8024e7a8:'format',0x8024e708:'mount',0x800ec08c:'set_param',0x800ee804:'allocate',0x800ee86c:'free',0x8025fc7c:'open',0x8025fd60:'read',0x8025fc84:'close',0x80087034:'filex_write',0x800a14f8:'log'}
def staging_case(elf,opts):
 import angr
 p=load_project(elf);events=[]
 def cstr(st,a):
  data=bytearray()
  for i in range(64):
   b=value(st,a+i,1)
   if b==b'\0':return data.decode()
   data+=b
  raise ValueError('unterminated')
 class Model(angr.SimProcedure):
  def run(self,*,api):
   st=self.state;a=[concrete(st,getattr(st.regs,f'a{i}')) for i in range(4)];kind=STAGING_APIS[api];result=0
   ev=dict(api=hex(api),kind=kind,ra=hex(concrete(st,st.regs.ra)))
   if kind=='size':
    ev['path']=cstr(st,a[0]);n=opts.get('size',len(INPUT));st.memory.store(a[1],struct.pack('<Q',n),size=8);ev['size']=n
   elif kind=='board':result=opts.get('board',2)
   elif kind in ('get_param','format','mount'):
    result_field=opts.get({'get_param':'ready','format':'format','mount':'mount'}[kind],1 if kind=='get_param' else 0)
    ev.update(selector=a[0],out_value=result_field);st.memory.store(a[1],struct.pack('<H',result_field),size=2)
   elif kind in ('set_param','set_long'):ev['arguments']=a[:2]
   elif kind=='allocate':
    assert a[0]==0 and a[1]==len(INPUT);result=0 if opts.get('alloc_failure') else STAGING_BUFFER;ev['size']=a[1]
   elif kind=='free':assert a[0]==STAGING_BUFFER;ev['pointer']=hex(a[0])
   elif kind=='open':
    ev.update(path=cstr(st,a[0]),mode=a[1]);result=opts.get('open_input' if a[1]==0 else 'open_output',0x101 if a[1]==0 else 0x102)
   elif kind=='read':
    assert a[:3]==[0x101,STAGING_BUFFER,len(INPUT)];result=opts.get('read',len(INPUT));data=INPUT[:result];st.memory.store(STAGING_BUFFER,data,size=len(data));ev['count']=a[2]
   elif kind=='close':ev['handle']=hex(a[0])
   elif kind=='filex_write':
    assert a[:3]==[0x102,STAGING_BUFFER,len(INPUT)];raw=value(st,STAGING_BUFFER,len(INPUT));assert raw==INPUT
    ev.update(handle=hex(a[0]),count=a[2],sha256=hashlib.sha256(raw).hexdigest());result=opts.get('write_status',0)
   events.append(dict(ev,result=result));return result
 for api in STAGING_APIS:p.hook(api,Model(num_args=0,api=api))
 st=new_state(p,angr);st.memory.store(STAGING_BUFFER,b'G'*len(INPUT));st.memory.store(0x807f268c,b'F:\\fwdc603p.bin\0')
 image=tuple((x.min_addr,x.max_addr+1) for x in p.loader.main_object.segments)
 guard(st,angr,((STAGING_BUFFER,STAGING_BUFFER+len(INPUT)),),image)
 st=execute(p,st,0x807f1acc,steps=8000)
 return dict(options=opts,result=concrete(st,st.regs.v0),events=events)

BRIDGE_CASES=[{}, {'burn':7},{'media_open':7},{'file_open':7},{'seek':7},{'read':7},{'read_extended':7},{'file_close':7}, {'outer':True}, {'outer':True,'burn':7},{'outer':True,'sync':0,'thread':0},{'outer':True,'sync':0,'thread':1}]
STAGING_CASES=[{},{'board':3},{'size':0},{'ready':0},{'format':7},{'mount':7},{'alloc_failure':True},{'open_input':0},{'read':95},{'open_output':0},{'write_status':7}]
REPLAY_SHA256='30d4750706adbc4771f2367619b038f314c20297c6bd2ad4f1c478a75d5597ee'

def validate_report(report):
 if not __debug__:raise RuntimeError('Replay requires assertions')
 assert report['input_sha256']==SHA and report['analysis_elf_sha256']==ELF_SHA256
 assert [r['options'] for r in report['bridge_cases']]==BRIDGE_CASES
 assert [r['result'] for r in report['bridge_cases']]==[0,254,254,254,254,254,254,0,1,1,0,1]
 assert [r['updating'] for r in report['bridge_cases']]==[0]*10+[1,1]
 assert [r['options'] for r in report['staging_cases']]==STAGING_CASES
 assert [r['result'] for r in report['staging_cases']]==[1,1]+[0]*9
 for row,drive in zip(report['staging_cases'][:2],('F','E'),strict=True):
  events=row['events']
  sized,=[e for e in events if e['kind']=='size']
  opened=[e for e in events if e['kind']=='open']
  assert sized['path']==r'F:\fwdc603p.bin' and sized['size']==96
  assert [e['path'] for e in opened]==[drive+r':\fwdc603p.bin',r'I:\UPG_FILE.ELF']
  assert events.index(sized)<events.index(opened[0])
  assert [e['count'] for e in events if e['kind'] in ('read','filex_write')]==[96,96]
 assert hashlib.sha256(json.dumps(report,sort_keys=True,separators=(',',':')).encode()).hexdigest()==REPLAY_SHA256

def replay(firmware,elf):
 if not __debug__:raise RuntimeError('Replay requires assertions')
 raw=firmware.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA:raise ValueError('Expected pinned original Q7 firmware')
 header=raw[0x100000:0x1000c0]
 assert hashlib.sha256(header).hexdigest()=='5269e3c1cd9cc8dedec0d35d27021c978fd1bc6fc1eaa329b9c0976e65c8c7c9'
 result=dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,header_original_offset='0x100000',header_bytes=192,header_sha256=hashlib.sha256(header).hexdigest(),staging_input_bytes=len(INPUT),staging_input_sha256=hashlib.sha256(INPUT).hexdigest(),bridge_cases=[bridge_case(elf,header,o) for o in BRIDGE_CASES],staging_cases=[staging_case(elf,o) for o in STAGING_CASES])
 validate_report(result)
 return result

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('firmware',type=Path);parser.add_argument('elf',type=Path)
 parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
 if not __debug__:parser.error('replay requires assertions')
 if lexists(args.output):parser.error('output must not exist')
 result=replay(args.firmware,args.elf)
 with args.output.open('x',encoding='utf-8') as handle:handle.write(json.dumps(result,indent=2)+'\n')
 print('PASS12 MAIN update bridge and11 file-staging cases')

if __name__=='__main__':main()
