"""Replay Q7 lens capability, position limits and focus completion on synthetic RAM."""
import argparse
import json
import struct
from pathlib import Path

from check_isp_registers import ELF_SHA256, load_project, RETURN_PC, STACK_TOP


GROUPS, OPERATIONS, RX = 0x80C25E78, 0x80C25EB8, 0x80C2A0D4
COMM_STATE, PLC_SPEC, PLC_STD, VDRC = 0x80C25E4B, 0x80C2A2F8, 0x80C2A398, 0x80C2A748
PLC_SPEC_OK, PLC_STD_OK, VD_OK = 0x80C2A73D, 0x80C2A73F, 0x80C2A746
DEST = 0x10002000
STATE, COUNT, NO_START_WAIT, AF_DONE = 0x804A147C, 0x804A1478, 0x804A1474, 0x8039592C
PENDING, RESULT, REQUEST_POSITION, REQUEST_OTHER = 0x80C2AA49, 0x80C2AA57, 0x80C2AA50, 0x80C2AA54

MAP_CASES = (
    (8, (2,), True, False),
    (0x40, (2,), True, False),
    (0x48, (2, 8), True, True),
    (8, (2, 8), False, True),
    (8, (8,), False, True),
    (8, (), False, False),
)
ACK_CASES = ((0, 0), (0, 1), (0, 100), (0, 101), (0, None), (1, None), (2, 1))
COMPLETION_CASES = (
    (0, 0, 0, (0,)), (1, 0, 0, (1, 2, 0)), (1, 0, 0, (2, 0)),
    (1, 5, 0, (0, 0, 0)), (1, 0, 0, (0,)*8), (1, 0, 1, (0, 0)),
    (2, 4, 0, (0x80, 0)), (2, 4, 0, (0,)), (3, 0, 0, (0,)),
)
DATA_CASES = ((0, 0, 0), (1, 1, 1), (1, 0, 7))


def speed_steps(status, raw):
    def f32(value):
        return struct.unpack('<f',struct.pack('<f',value))[0]

    return int(f32(f32(raw*f32(0.004166666883975267))*100)) if status else 0


def reference():
    maps = []
    for comm, groups, af, extended in MAP_CASES:
        specs_command = 7 if extended else 2
        maps.append(dict(communications_state=comm, supported_groups=list(groups),
                         group2_operation4=int(af), group8_operation7=int(extended),
                         expected_af=int(bool(comm & 8) and af), primary_spec_command=specs_command,
                         expected_native_search_result=1 if af else 7,
                         observed_map_requests=[[0, 1, 0, 1], *([0, 1, g, 0] for g in groups)]))
    data = [dict(spec_valid=s, standard_valid=t, vd_status=v,
                 lens_id=0x1234, over_infinite_limit=0xFFFEFFFF, current=0x81234567,
                 minimum=0x00123456, max_speed=0x8123, min_speed=0x0034, motion=2)
            for s,t,v in DATA_CASES]
    speed = [dict(status=status,raw_u16=raw,expected_steps=speed_steps(status,raw))
             for status,raw in ((0,0),(1,0),(0,240),(1,240),(7,0x8000),(1,0xFFFF),(1,0x8123))]
    ack = [dict(inhibit_byte=i, acknowledge_after_waits=a, waits=0 if i==1 else (a if a is not None else 101),
                result=8 if i==1 else (6 if a is None or a>=101 else 1),
                messages=[] if i==1 else [7]) for i,a in ACK_CASES]
    completions = []
    for initial, count, bypass, samples in COMPLETION_CASES:
        state, initial_count, steps = initial, count, []
        for motion in samples:
            completed = state==2 and motion==0
            if state == 1:
                if motion==1 or count>=6 or bypass:
                    state=2
                count+=1
            elif completed:
                state=0
            steps.append(dict(motion=motion,state=state,start_poll_count=count,
                              af_complete=int(completed),commands=[[0x6003F,0]] if completed else []))
        completions.append(dict(initial_state=initial,initial_count=initial_count,
                                disable_start_wait=bypass,steps=steps))
    return dict(
        analysis_elf_sha256=ELF_SHA256,
        scope='Concrete original instructions for map decode/capability, big-endian cached data, command acknowledgement and motion completion.',
        capability_cases=maps, data_cases=data, speed_cases=speed,
        acknowledgement_cases=ack, completion_cases=completions,
        modeled_boundaries={
            'capability':['0x80111354 LLC','0x80111214 lens transport','0x8010fd10 link frequency',
                          '0x8010f8e4 link configuration','0x8010f4f0 retry delay',
                          '0x80110c50 lower transport only for original command admission'],
            'data':[],
            'speed':[],
            'acknowledgement':['0x80116af8 queue send','0x8010f4f0 scheduler wait/worker response injection'],
            'completion':['0x80436a40 focus-mode query','0x80436b7c focus-ring setting',
                          '0x8040a008 capture command recipient; record arguments only'],
        },
    )


def put(state, address, value, size=4):
    state.memory.store(address,value.to_bytes(size,'little'))


def get(state,address,size=4):
    value=state.memory.load(address,size,endness='Iend_LE')
    assert not value.symbolic
    return state.solver.eval(value)


def make_state(project,angr):
    state=project.factory.blank_state(add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS})
    state.regs.sp=STACK_TOP
    for start,size in ((STACK_TOP-0x800,0x820),(0x80C25E40,0x4C80),(DEST,0x100),
                       (0x804A1470,0x20),(0x8039592C,4),(0x80C6AAE4,0x18)):
        state.memory.store(start,bytes(size))
    return state


def call(project,state,address,*args):
    state.regs.pc,state.regs.ra=address,RETURN_PC
    for index,value in enumerate(args[:4]):
        setattr(state.regs,f'a{index}',value)
    for index,value in enumerate(args[4:],start=4):
        put(state,STACK_TOP+4*index,value)
    sim=project.factory.simgr(state,save_unconstrained=True)
    sim.explore(find=RETURN_PC,n=2400)
    assert len(sim.found)==1 and not sim.active and not sim.errored and not sim.unconstrained,(hex(address),sim.errored)
    state=sim.found[0]
    assert state.solver.eval(state.regs.sp)==STACK_TOP
    assert not state.regs.v0.symbolic
    return state,state.solver.eval(state.regs.v0)


def capability(project,angr,cases):
    class LLC(angr.SimProcedure):
        def run(self,a0,command,send,receive):
            st=self.state
            cmd=st.solver.eval(command)
            st.globals['llc'].append(cmd)
            assert st.solver.eval(a0)==0
            st.memory.store(receive,bytes([1])+bytes(15))
            return 1

    class Transport(angr.SimProcedure):
        def run(self,a0,a1,a2,a3):
            st=self.state
            args=[st.solver.eval(a) for a in (a0,a1,a2,a3)]
            st.globals['transport'].append(args)
            receive=get(st,st.solver.eval(st.regs.sp)+0x14)
            fixture=st.globals['fixture']
            if args==[0,1,0,1]:
                bits=sum(1<<g for g in fixture['supported_groups'])
                assert receive==RX
                st.memory.store(receive,bits.to_bytes(8,'little'))
            elif args[:2]==[0,1] and args[3]==0:
                assert receive==RX and args[2] in fixture['supported_groups']
                bits={2:fixture['group2_operation4']<<4,8:fixture['group8_operation7']<<7}[args[2]]
                st.memory.store(receive,bits.to_bytes(32,'little'))
            else:
                assert args==[0,1,8,fixture['primary_spec_command']]
                st.memory.store(receive,b'\0\0\x12\x34'+bytes(116))
            return 1

    class Noop(angr.SimProcedure):
        def run(self):
            return 0

    for address,stub in ((0x80111354,LLC()),(0x80111214,Transport()),(0x8010FD10,Noop()),
                         (0x8010F8E4,Noop()),(0x8010F4F0,Noop())):
        project.hook(address,stub)
    decoded_states=[]
    for fixture in cases:
        state=make_state(project,angr)
        state.globals['fixture']=fixture
        state.globals['llc'],state.globals['transport']=[],[]
        state,result=call(project,state,0x80111448)
        assert result==1 and state.globals['llc']==[1,2,4,5]
        assert state.globals['transport']==fixture['observed_map_requests']
        assert get(state,0x80C2A2D9,1)==1
        for group in range(64):
            assert get(state,GROUPS+group,1)==int(group in fixture['supported_groups'])
        for group,operation,key in ((2,4,'group2_operation4'),(8,7,'group8_operation7')):
            assert get(state,OPERATIONS+256*group+operation,1)==fixture[key]
        put(state,COMM_STATE,fixture['communications_state'],1)
        state,result=call(project,state,0x8042E278)
        assert result==fixture['expected_af']
        state,result=call(project,state,0x80113B60,PLC_SPEC)
        assert result==1 and state.globals['transport'][-1]==[0,1,8,fixture['primary_spec_command']]
        assert get(state,0x80C2A73E,1)==fixture['group8_operation7']
        put(state,PLC_SPEC_OK,1,1)
        state,result=call(project,state,0x801122D8,DEST)
        assert result==1 and get(state,DEST,2)==0x1234
        decoded_states.append(state)
    for address in (0x80111354,0x80111214,0x8010FD10,0x8010F8E4,0x8010F4F0):
        project.unhook(address)

    class SearchBoundary(angr.SimProcedure):
        def run(self,mode,send_count,receive_count):
            st=self.state
            st.globals['forwarded']+=1
            assert get(st,0x80C29EC8)==0x04020100
            assert st.solver.eval(send_count)==3
            return 1

    project.hook(0x80110C50,SearchBoundary())
    for fixture,state in zip(cases,decoded_states,strict=True):
        state.globals['forwarded']=0
        state,result=call(project,state,0x80111214,0,1,2,4,DEST+0x20,DEST+0x40)
        assert result==fixture['expected_native_search_result']
        assert state.globals['forwarded']==int(result==1)
    project.unhook(0x80110C50)


def cached_data(project,angr,cases,speed_cases):
    for case in cases:
        state=make_state(project,angr)
        for address,value in ((PLC_SPEC_OK,case['spec_valid']),(PLC_STD_OK,case['standard_valid']),
                              (VD_OK,case['vd_status']),(VDRC,case['motion'])):
            put(state,address,value,1)
        for entry,address,width,key,validity in (
            (0x801122D8,PLC_SPEC+2,2,'lens_id','spec_valid'),
            (0x801125DC,PLC_STD+0x47,4,'over_infinite_limit','standard_valid'),
            (0x801124C0,VDRC+1,4,'current','vd_status'),
            (0x8011252C,VDRC+0x7A,4,'minimum','vd_status'),
            (0x8011264C,VDRC+0x91,2,'max_speed','vd_status'),
            (0x80112678,VDRC+0x93,2,'min_speed','vd_status'),
            (0x80112514,VDRC,1,'motion','vd_status'),
        ):
            state.memory.store(address,case[key].to_bytes(width,'big'))
            put(state,DEST,0)
            state,result=call(project,state,entry,DEST)
            assert get(state,DEST,width)==case[key] and result==case[validity],(hex(entry),case)


    for fixture in speed_cases:
        state=make_state(project,angr)
        put(state,VD_OK,fixture['status'],1)
        state.memory.store(VDRC+0x91,fixture['raw_u16'].to_bytes(2,'big'))
        _,result=call(project,state,0x80378E98)
        assert result==fixture['expected_steps'],fixture


def acknowledgement(project,angr,cases):
    def reply(state):
        put(state,PENDING,0,1)
        put(state,RESULT,1,1)

    class Queue(angr.SimProcedure):
        def run(self,command):
            st=self.state
            st.globals['messages'].append(st.solver.eval(command))
            assert get(st,PENDING,1)==1
            if st.globals['ack']==0:
                reply(st)
            return 0

    class Wait(angr.SimProcedure):
        def run(self,ticks):
            st=self.state
            assert st.solver.eval(ticks)==1
            st.globals['waits']+=1
            if st.globals['waits']==st.globals['ack']:
                reply(st)
            return 0

    project.hook(0x80116AF8,Queue())
    project.hook(0x8010F4F0,Wait())
    for fixture in cases:
        state=make_state(project,angr)
        put(state,0x80C2A2E2,fixture['inhibit_byte'],1)
        state.globals['ack']=fixture['acknowledge_after_waits']
        state.globals['waits'],state.globals['messages']=0,[]
        state,result=call(project,state,0x8011357C,0x81234567,0x2001)
        assert (result,state.globals['waits'],state.globals['messages'])==(
            fixture['result'],fixture['waits'],fixture['messages'])
        assert get(state,REQUEST_POSITION)==0x81234567 and get(state,REQUEST_OTHER,2)==0x2001
    project.unhook(0x80116AF8)
    project.unhook(0x8010F4F0)


def completion(project,angr,cases):
    class Setting(angr.SimProcedure):
        def run(self,*,value):
            return value

    class Command(angr.SimProcedure):
        def run(self,command,arg):
            st=self.state
            st.globals['commands'].append([st.solver.eval(command),st.solver.eval(arg)])
            return 1

    project.hook(0x80436A40,Setting(value=1))
    project.hook(0x80436B7C,Setting(value=0))
    project.hook(0x8040A008,Command())
    for fixture in cases:
        state=make_state(project,angr)
        state,callback=call(project,state,0x803786E8)
        assert callback==0x803786B4
        put(state,0x80C6AAEC,0x8040A008)
        put(state,0x80C6AAF4,callback)
        put(state,STATE,fixture['initial_state'],1)
        put(state,COUNT,fixture['initial_count'])
        put(state,NO_START_WAIT,fixture['disable_start_wait'],1)
        for step in fixture['steps']:
            put(state,VDRC,step['motion'],1)
            put(state,AF_DONE,0,1)
            state.globals['commands']=[]
            state,_=call(project,state,0x8042E5AC)
            assert (get(state,STATE,1),get(state,COUNT),get(state,AF_DONE,1),state.globals['commands'])==(
                step['state'],step['start_poll_count'],step['af_complete'],step['commands'])


def replay(elf):
    if not __debug__:
        raise RuntimeError('replay requires assertions')
    import angr
    project=load_project(elf)
    if project.arch.name!='MIPS32' or project.arch.memory_endness!='Iend_LE':
        raise ValueError('expected little-endian MIPS32 ELF')
    report=reference()
    capability(project,angr,report['capability_cases'])
    cached_data(project,angr,report['data_cases'],report['speed_cases'])
    acknowledgement(project,angr,report['acknowledgement_cases'])
    completion(project,angr,report['completion_cases'])
    return dict(**report,engine=f'angr {angr.__version__} / VEX')


def validate_report(report):
    engine=report.get('engine','')
    if not isinstance(engine,str) or not engine.startswith('angr ') or not engine.endswith(' / VEX'):
        raise ValueError('invalid replay engine')
    if report!=dict(**reference(),engine=engine):
        raise ValueError('lens policy replay differs from reference')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf',type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    if args.output.exists():
        parser.error('output must not exist')
    report=replay(args.elf)
    validate_report(report)
    with args.output.open('x',encoding='utf-8',newline='\n') as stream:
        json.dump(report,stream,indent=2)
        stream.write('\n')
    print('6 map, 3 cached-data, 7 speed, 7 acknowledgement and 9 completion fixtures PASS')


if __name__=='__main__':
    main()
