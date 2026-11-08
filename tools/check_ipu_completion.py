"""Bounded replay of Q7 IPU queue, IRQ, worker and completion callbacks."""
import argparse
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256, load_project

DRIVER, PROCESSOR, TASK, OBSERVER = 0x10001000, 0x10002000, 0x10003000, 0x10008000
STACK, RETURN = 0x70008000, 0x0BADF000
PATH_EVENT, EARLY_EVENT = 0x815A1BC4, 0x815CCC74
SCOPE = ('Original queue wrapper, IRQ handler, one driver iteration and observer chain; '
         'synthetic objects and injected API outcomes, no camera or RTOS scheduling.')


def reference():
    return dict(analysis_elf_sha256=ELF_SHA256, scope=SCOPE,
        irq_cases=[dict(end=n, counter=c, next_counter=c+1,
                       flags=([EARLY_EVENT, 0x40000000, 0] if n>=2 and c==n-2 else []) +
                             [DRIVER+0x30C, 1, 0])
                   for n,c in ((0,0),(1,0),(2,0),(4,0),(4,1),(4,2),(4,3))],
        queue_cases=[dict(status=s, halted=s!=0) for s in (0,11)],
        worker_cases=[dict(wait_status=s, timeout_ticks=5000, halted=s!=0,
                           mmio=[[0xB60001CC,1],[0xB6000000,0]], notification=(s==0))
                      for s in (0,7)],
        callback_cases=[dict(pass_index=i, completed_passes=i+1,
                             path_done=(i==3), flags=([0x04000000] if i==1 else ([1] if i==3 else []))) for i in range(4)],
        subimage_cases=[dict(count=n, queued_again=(n==2), notification=(4 if n==2 else 2))
                        for n in (1,2)],
        modeled_functions={
            '0x800d7c04':'queue_send status and captured message',
            '0x800cf768':'queue_receive supplies one task pointer',
            '0x800d8ea8':'event_flags_set captures arguments',
            '0x800cc3b4':'event_flags_get supplies success or timeout',
            '0x800cbee4':'mutex_get', '0x800d193c':'mutex_put',
            '0x800d9ac8':'counter_get', '0x800d0aa4':'IRQ mask',
            '0x8035285c':'debug dump', '0x800a1310':'diagnostic print',
            '0x80357098':'WriteAll records invocation; device/filter programming omitted',
            '0x80334054':'PowerOff', '0x80357f28':'CalculateHeight returns synthetic 128',
            '0x80351890':'CommitSubImage', '0x80339600':'FreeTempResources',
            '0x80339ea0':'endianity follow-up'},
        limitations=[
            'IRQ calls and event-get results are injected, not hardware observations.',
            'Callback cases use four non-null task slots, one subimage per task, mode 0 and CBC 0.',
            'Geometry, WriteAll, cleanup, IRQ acknowledge and physical pixel results are outside this replay.',
        ])


def replay(elf):
    if not __debug__:
        raise RuntimeError('Replay requires assertions')
    import angr
    project=load_project(elf)
    events=[]
    queue_status=wait_status=0

    def val(state, x):
        if isinstance(x,int): return x
        assert not x.symbolic
        return state.solver.eval(x)

    def read(state, addr):
        return val(state,state.memory.load(addr,4,endness='Iend_LE'))

    def word(state, addr, value):
        state.memory.store(addr,struct.pack('<I',value))

    class Model(angr.SimProcedure):
        def run(self, a0,a1,a2,a3, *, name):
            st=self.state
            if name=='send':
                events.append(['send',val(st,a0),read(st,val(st,a1)),val(st,a2)])
                return queue_status
            if name=='receive':
                word(st,val(st,a1),TASK)
                events.append(['receive',val(st,a0),val(st,a2)])
            elif name=='set':
                events.append(['set',val(st,a0),val(st,a1),val(st,a2)])
            elif name=='wait':
                events.append(['wait',val(st,a0),val(st,a1),val(st,a2),read(st,val(st,st.regs.sp)+16)])
                word(st,val(st,a3),1 if wait_status==0 else 0)
                return wait_status
            elif name=='height':
                return 128
            elif name in ('write','poweroff','subimage','free'):
                events.append([name])
            return 0

    hooks={0x800D7C04:'send',0x800CF768:'receive',0x800D8EA8:'set',0x800CC3B4:'wait',
           0x800CBEE4:'noop',0x800D193C:'noop',0x800D9AC8:'noop',0x800D0AA4:'noop',
           0x8035285C:'noop',0x800A1310:'noop',0x80357098:'write',0x80334054:'poweroff',
           0x80357F28:'height',0x80351890:'subimage',0x80339600:'free',0x80339EA0:'noop'}
    for pc,name in hooks.items():
        project.hook(pc,Model(name=name))

    def blank():
        st=project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
        st.regs.sp=STACK
        st.memory.store(STACK-0x1000,bytes(0x2000))
        st.memory.store(DRIVER,bytes(0x8000))
        word(st,0xB0802024,0)
        return st

    def call(st,pc,args,stop=RETURN):
        st.regs.pc,st.regs.ra=pc,RETURN
        for i,arg in enumerate(args):
            setattr(st.regs,f'a{i}',arg)
        sim=project.factory.simgr(st)
        sim.explore(find=stop,n=1024)
        assert len(sim.found)==1 and not sim.active and not sim.errored, str(sim)
        return sim.found[0]

    expected=reference()
    for case in expected['irq_cases']:
        st=blank();events.clear()
        word(st,DRIVER+0x348,case['end']);word(st,DRIVER+0x34C,case['counter'])
        st=call(st,0x8033416C,[DRIVER])
        assert read(st,DRIVER+0x34C)==case['next_counter']
        assert [v for e in events for v in e[1:]]==case['flags']

    for case in expected['queue_cases']:
        st=blank();events.clear();queue_status=case['status']
        word(st,TASK+0x1C8,DRIVER)
        st=call(st,0x803519D0,[TASK],0x800D6AA4 if case['halted'] else RETURN)
        assert events==[['send',DRIVER+0x224,TASK,0]]
    queue_status=0

    # Worker control flow is tested independently of the callback chain below.
    project.hook(0x800AD16C,Model(name='noop'))
    for case in expected['worker_cases']:
        st=blank();events.clear();wait_status=case['wait_status']
        word(st,DRIVER+0x10,1);word(st,TASK,0x804FF1E0)
        writes=[]
        def capture(s):
            addr=val(s,s.inspect.mem_write_address)
            if 0xB6000000<=addr<0xB6001000:
                writes.append([addr,val(s,s.inspect.mem_write_expr)])
        st.inspect.b('mem_write',when=angr.BP_BEFORE,action=capture)
        st=call(st,0x803341F0,[DRIVER],0x800D6AA4 if case['halted'] else 0x803342DC)
        assert writes==case['mmio']
        assert read(st,DRIVER+0x8C)==TASK
        assert events[:4]==[['receive',DRIVER+0x224,0xFFFFFFFF],['set',DRIVER+0x30C,0xFFFFFFFE,2],
                           ['write'],['wait',DRIVER+0x30C,1,1,5000]]
        assert (['poweroff'] in events)==case['notification']
        if not case['halted']:
            assert [val(st,getattr(st.regs,f'a{i}')) for i in range(3)]==[DRIVER,2,TASK]
    project.unhook(0x800AD16C)

    st=blank()
    word(st,PROCESSOR+8,0x804FEAB4)
    word(st,PROCESSOR+4,OBSERVER);word(st,OBSERVER,0x804FCE40);word(st,OBSERVER+4,0x801BCB88)
    word(st,PROCESSOR+0x308,4);word(st,PROCESSOR+0x2F0,1)
    for i in range(4):
        task=TASK+0x400*i
        word(st,PROCESSOR+0x204+4*i,task)
        word(st,task,0x804FF1E0);word(st,task+8,0x804FF228)
        word(st,task+4,PROCESSOR+8);word(st,task+0x224,1)
    for case in expected['callback_cases']:
        events.clear();task=TASK+0x400*case['pass_index'];word(st,DRIVER+4,task+8)
        st=call(st,0x800AD16C,[DRIVER,2,task])
        assert read(st,PROCESSOR+0x304)==case['completed_passes']
        assert read(st,task+0x220)==0
        assert [e for e in events if e[0]=='set']==[['set',PATH_EVENT,f,0] for f in case['flags']], (case,events)
        assert (['free'] in events)==case['path_done']

    # Isolate subimage branches; observer has the real CObserverWrapper vtable.
    for case in expected['subimage_cases']:
        st=blank();events.clear()
        word(st,TASK,0x804FF1E0);word(st,TASK+4,OBSERVER);word(st,TASK+0x1C8,DRIVER)
        word(st,OBSERVER,0x804FCE40);word(st,OBSERVER+4,0x801BCB88)
        word(st,TASK+0x224,case['count']);word(st,TASK+0x234,1)
        st=call(st,0x80357C50,[TASK,DRIVER,2,TASK])
        assert any(e[0]=='send' for e in events)==case['queued_again']
        assert [e for e in events if e[0]=='set']==[['set',PATH_EVENT,0x10000000 if case['queued_again'] else 1,0]]
    return expected


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('elf',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args()
    if args.output.exists(): p.error('output must not exist')
    result=replay(args.elf)
    with args.output.open('x',encoding='utf-8') as out:
        out.write(json.dumps(result,indent=2)+'\n')
    print('17 queue/IRQ/worker/callback/subimage cases PASS')


if __name__=='__main__': main()
