"""Replay original Q7 AF search/stop, lens worker and completion predicates."""
import argparse
import json
from os.path import lexists
from pathlib import Path

from check_isp_registers import ELF_SHA256, RETURN_PC, STACK_TOP, load_project
from check_lens_policy import AF_DONE, COUNT, STATE, VDRC, VD_OK, get, make_state, put
from check_lens_readiness import AF_GET, AF_OP, COMM_STATE, LINK, MAP_READY, RESET, SINGLE, TX, call, num, read, record
from q7_symbols import SHA


DRIVE, DISPATCH_RETURN, CALLBACK = 0x8037EB78, 0x8040A460, 0x8042E5AC
NOTIFY, COMPLETE, WAIT_STOP = 0x8040A008, 0x803786B4, 0x8042E4C4
THREAD, NEXT_RECEIVE = 0x80116980, 0x801169AC
QUEUE_SEND, QUEUE_RECEIVE, DELAY = 0x80125D0C, 0x80125CEC, 0x8010F4F0
QUEUE_POINTER, QUEUE = 0x80C2AA88, 0x10005000
SEARCH_SEND_RETURN, STOP_SEND_RETURN = 0x801134EC, 0x8011366C
AF_COMMAND, EXIT_WAIT = 0x8037E218, 0x803787E4
EVENT_SET, EVENT_WAIT, EVENT_HANDLE = 0x80125C24, 0x80125BE0, 0x10006000
SEQ, SLEEPING, STOP_COMMAND = 0x80445549, 0x80395A21, 0x80395A22
BK_CONTROL, BK_CANCEL = 0x80395A12, 0x80395A64
CAF_ENABLED, CAF_QUIT, STOP_RELEASE = 0x80C24BAD, 0x80C24BAE, 0x80C24BC0
SEARCH_PENDING, STOP_PENDING = 0x80C2AA48, 0x80C2AA4A
SEARCH_RESULT, STOP_RESULT = 0x80C2AA56, 0x80C2AA58
STOP_OP, REGULAR_OP, INHIBIT, CAPTURE_PHASE = AF_OP+2, AF_OP-0xF8, 0x80C2A2E2, 0x80445200
LENS_RAM, LENS_BYTES = 0x80C25E40, 0x4C80
SETUP = dict(communications_state=8, map_ready=1, search_allowed=1, stop_allowed=1,
             actuator_inhibit=0, regular_allowed=1, capture_phase=2, cached_motion=0, vd_validity=1)
SCOPE = (
    "Original LensDriveControl, capture notification/dispatch, search and stop setters, lens worker "
    "from its entry through one queued message and upper transport admission. Original live-view and "
    "focus-stop predicates consume RAM telemetry. The original AF stop notification selector and "
    "sequence-exit wait are separate checks. Link replies and wait/queue/event delivery are synthetic."
)
MODELED = {
    hex(QUEUE_SEND): "Capture the attempted lens message and queue handle and return fixture submission status.",
    hex(QUEUE_RECEIVE): "Deliver the captured word to the native worker on the separate worker state.",
    hex(DELAY): "Record native tick arguments. Deliver an accepted message to the worker at its fixture wait count, or supply the next focus-stop sample.",
    hex(LINK): "Record original command and configured TX/RX lengths; supply lower status and leave the zero-initialized shared RX buffer unchanged.",
    hex(EVENT_SET): "Record AF thread wake event without waking an RTOS thread.",
    hex(EVENT_WAIT): "Record AF sequence-exit event, mode and timeout; supply fixture status and result bits.",
}
# Drive action tuple is (mode, wait-for-motion flag, delivery poll or None, lower status, setter return).
# Poll action sets (motion, validity); (None, None) uses the existing cache unchanged.
CASES = (
    ("search-ack-then-motion", {}, (("drive",0,1,1,1,1), ("poll",1,1), ("poll",2,1), ("poll",0,1))),
    ("phase-four-conditional-advance", {"capture_phase":4}, (("drive",0,1,1,1,1), ("poll",1,1), ("poll",0,1))),
    ("search-map-denied-then-invalid-zero", {"search_allowed":0, "vd_validity":0},
     (("drive",0,1,1,1,7), *[("poll",None,None)]*8)),
    ("search-link-error-then-failed-regular-zero", {"cached_motion":2},
     (("drive",0,1,1,4,4), ("regular-failure",), *[("poll",None,None)]*8)),
    ("search-late-worker-at-timeout", {}, (("drive",0,1,101,1,6),)),
    ("search-inhibited-immediate-notify", {"actuator_inhibit":1}, (("drive",0,0,None,1,8),)),
    ("search-ready-clear-forwarded", {"communications_state":0,"map_ready":0,"search_allowed":0},
     (("drive",0,1,1,1,1),)),
    ("stop-ack-while-cache-moving", {},
     (("drive",0,1,1,1,1), ("poll",1,1), ("drive",1,1,1,1,1), ("poll",0,1))),
    ("stop-map-denied-clears-check", {"stop_allowed":0},
     (("drive",0,1,1,1,1), ("poll",1,1), ("drive",1,1,1,1,7), ("poll",0,1))),
    ("stop-timeout-clears-check", {},
     (("drive",0,1,1,1,1), ("poll",1,1), ("drive",1,1,None,1,6), ("poll",0,1))),
    ("reset-zero-during-motion-check", {},
     (("drive",0,1,1,1,1), ("poll",1,1), ("reset",), ("poll",None,None))),
    ("search-queue-rejected", {"queue_send_result":0}, (("drive",0,1,None,1,6),)),
)
WAITS = (
    ("invalid-zero", (0,0), ()),
    ("invalid-moving-then-zero", (1,0), ((1,0),(0,0))),
    ("nonzero-through-bound", (0x80,1), ((0x80,1),)*4),
)
# (name, entry, sequence flag, sleeping flag, BK control guard, wait return)
ABORTS = (
    ("notify-no-sequence", "notify", 0, 1, 0, None),
    ("notify-active-awake", "notify", 1, 0, 0, 1),
    ("notify-active-sleeping", "notify", 1, 1, 0, 0),
    ("notify-deferred-bk-cancel", "notify", 1, 1, 1, None),
    ("separate-exit-wait", "exit-wait", 1, 1, 0, 1),
)


def lower_event(mode, status):
    if mode == 2:
        return dict(command=[0,1,1,12], transport_mode=2, tx_bytes=1, rx_bytes=160, payload_hex="00", result=status)
    return dict(command=[0,1,2,4 if mode == 0 else 6],
                transport_mode=2 if mode == 0 else 1, tx_bytes=3 if mode == 0 else 0, rx_bytes=1 if mode == 0 else 0,
                payload_hex="123456" if mode == 0 else "", result=status)


def reference():
    cases = []
    for name, setup, steps in CASES:
        inputs = SETUP | setup
        af = int(bool(inputs["communications_state"] & 8 and inputs["search_allowed"]))
        motion, validity, phase = (inputs[k] for k in ("cached_motion","vd_validity","capture_phase"))
        state, count, done, rows = 0, 0, 0, []
        for action, *args in steps:
            notifications = []
            row = dict(action=action)
            if action == "drive":
                mode, wait, delivery, link_status, status = args
                enabled = inputs["actuator_inhibit"] != 1
                delivered = enabled and inputs.get("queue_send_result",1) == 1 and delivery is not None
                admitted = inputs["map_ready"] != 1 or inputs["search_allowed" if mode == 0 else "stop_allowed"]
                worker_result = (7 if not admitted
                                 else link_status) if delivered else None
                state, count, done = int(wait == 1 and mode != 1), 0, int(wait != 1)
                notifications = [0x6003C]
                if mode == 0:
                    notifications.append(0x6003E)
                    if phase == 2:
                        phase = 3
                if done:
                    notifications.append(0x10060032)
                row.update(mode=mode, wait_for_motion=wait, worker_delivery_wait=delivery,
                           outer_return=1, setter_return=status,
                           queue_message=[6 if mode == 0 else 8] if enabled else [],
                           waits=0 if not enabled else (delivery if delivered else 101),
                           worker_result=worker_result, worker_pending=int(enabled and not delivered),
                           link=[] if not delivered or worker_result == 7 else [lower_event(mode,link_status)])
                if enabled and "queue_send_result" in inputs:
                    row["queue_wrapper_return"] = inputs["queue_send_result"]
            elif action == "poll":
                if args[0] is not None:
                    motion, validity = args
                if state == 1:
                    if motion == 1 or count >= 6:
                        state = 2
                    count += 1
                elif state == 2 and motion == 0:
                    state, done = 0, 1
                    notifications = [0x6003F,0x10060032]
                    if phase == 4:
                        phase = 5
            elif action == "regular-failure":
                motion = 0
                row.update(result=4, link=[lower_event(2,4)])
            else:
                assert action == "reset"
                motion, validity = 0, 0
                row.update(communications_state=0,map_ready=0)
            row.update(cached_motion=motion,vd_validity=validity,motion_check_state=state,start_count=count,
                       af_complete=done,capture_phase=phase,notifications=notifications)
            rows.append(row)
        cases.append(dict(name=name, setup=inputs, af_enable=af, steps=rows))
    waits = [dict(name=name, initial=list(initial), samples=[list(x) for x in samples], waits=len(samples),
                  returned=int(name != "nonzero-through-bound"),
                  stop_pc="0x8042e4d4" if name=="nonzero-through-bound" else hex(RETURN_PC))
             for name,initial,samples in WAITS]
    aborts = []
    for name,entry,active,sleeping,bk,status in ABORTS:
        stop = entry=="notify" and bk==0
        should_wait = active==1 and not bk
        events = [["set",16]] if should_wait and sleeping==1 else []
        if should_wait:
            events.append(["wait",8,1,0xFFFFFFFF,int(stop),status])
        aborts.append(dict(name=name,entry=entry,sequence=active,sleeping=sleeping,bk_control=bk,
                           events=events,stop_command=int(should_wait),stop_release_after=0,
                           enable_caf=int(not stop),quit_caf=int(stop),bk_cancel=bk))
    return dict(input_sha256=SHA, analysis_elf_sha256=ELF_SHA256, scope=SCOPE, modeled_boundaries=MODELED,
                command_cases=cases, wait_cases=waits, abort_cases=aborts)


def validate_report(report):
    """Validate public replay metadata without firmware or angr."""
    engine = report.get("engine")
    if (not isinstance(engine,str) or not engine.startswith("angr ") or not engine.endswith(" / VEX")
            or report != dict(reference(),engine=engine)):
        raise ValueError("AF completion replay differs from the reference")


def install(project, worker, angr):
    class Transport(angr.SimProcedure):
        def run(self, mode, tx_length, rx_length):
            st = self.state
            cmd = list(read(st,TX,4))
            length = num(st,tx_length)
            expected = {(0,1,2,4):(2,3,1), (0,1,2,6):(1,0,0), (0,1,1,12):(2,1,160)}
            shape = (num(st,mode),length,num(st,rx_length))
            assert shape == expected[tuple(cmd)], (cmd,shape)
            status = st.globals["link_result"]
            body = read(st,TX+4,length).hex() if length else ""
            record(st,"link",dict(command=cmd,transport_mode=shape[0],tx_bytes=length,rx_bytes=shape[2],payload_hex=body,result=status))
            return status

    class Receive(angr.SimProcedure):
        def run(self, queue, destination, wait):
            st = self.state
            assert num(st,queue)==QUEUE and num(st,wait)==0xFFFFFFFF and not st.globals.get("delivered")
            put(st,num(st,destination),st.globals["message"])
            st.globals["delivered"] = True
            return 1

    class Send(angr.SimProcedure):
        def run(self, queue, source, wait):
            st = self.state
            assert num(st,queue)==QUEUE and num(st,wait)==0
            command = get(st,num(st,source))
            assert command in (6,8) and not st.globals.get("messages")
            record(st,"messages",command)
            return st.globals.get("queue_send_result",1)

    def run_worker(parent):
        message, = parent.globals["messages"]
        st = make_state(worker,angr)
        st.memory.store(LENS_RAM,read(parent,LENS_RAM,LENS_BYTES),inspect=False)
        st.globals["link_result"], st.globals["message"] = parent.globals["link_result"], message
        st.regs.pc,st.regs.ra = THREAD,RETURN_PC
        sim = worker.factory.simgr(st,save_unconstrained=True)
        sim.explore(find=lambda s: s.addr==NEXT_RECEIVE and s.globals.get("delivered",False),n=500)
        assert len(sim.found)==1 and not sim.active and not sim.errored and not sim.unconstrained, sim.errored
        st = sim.found[0]
        assert num(st,st.regs.sp)==STACK_TOP-0x30
        pending,result = (SEARCH_PENDING,SEARCH_RESULT) if message==6 else (STOP_PENDING,STOP_RESULT)
        assert get(st,pending,1)==0
        parent.memory.store(LENS_RAM,read(st,LENS_RAM,LENS_BYTES),inspect=False)
        parent.globals["worker_result"] = get(st,result,1)
        parent.globals["link"] = st.globals.get("link",())

    class Delay(angr.SimProcedure):
        def run(self, ticks):
            st = self.state
            assert num(st,ticks)==1
            index = st.globals.get("wait_count",0)
            st.globals["wait_count"] = index+1
            if "samples" in st.globals:
                motion, validity = st.globals["samples"][index]
                put(st,VDRC,motion,1)
                put(st,VD_OK,validity,1)
            elif st.globals.get("queue_send_result",1)==1 and st.globals.get("delivery")==index+1:
                run_worker(st)
            return 0

    class EventSet(angr.SimProcedure):
        def run(self, handle, mask):
            st = self.state
            assert num(st,handle)==EVENT_HANDLE
            record(st,"caf_events",["set",num(st,mask)])
            return 1

    class EventWait(angr.SimProcedure):
        def run(self, handle, mask, received, option):
            st = self.state
            timeout = get(st,num(st,st.regs.sp)+16)
            assert num(st,handle)==EVENT_HANDLE
            status = st.globals["event_status"]
            record(st,"caf_events",["wait",num(st,mask),num(st,option),timeout,get(st,STOP_RELEASE,1),status])
            put(st,num(st,received),num(st,mask) if status else 0)
            return status

    project.hook(EVENT_SET,EventSet())
    project.hook(EVENT_WAIT,EventWait())
    project.hook(QUEUE_SEND,Send())
    project.hook(DELAY,Delay())
    project.hook(LINK,Transport())
    worker.hook(QUEUE_RECEIVE,Receive())
    worker.hook(LINK,Transport())


def fixture(project,angr,inputs):
    st = make_state(project,angr)
    for start,size in ((0x80C17E00,0x20), (0x80C24BA0,0x520), (0x8012D860,0xC0),
                       (0x8153C000,0x1000), (0x80C6AAD4,0x10), (0x80C6B66C,1), (0x80C4A318,2)):
        st.memory.store(start,bytes(size))
    for address,key in ((COMM_STATE,"communications_state"),(MAP_READY,"map_ready"),(AF_OP,"search_allowed"),
                        (STOP_OP,"stop_allowed"),(REGULAR_OP,"regular_allowed"),(INHIBIT,"actuator_inhibit"),(VDRC,"cached_motion"),(VD_OK,"vd_validity")):
        put(st,address,inputs[key],1)
    put(st,CAPTURE_PHASE,inputs["capture_phase"])
    put(st,QUEUE_POINTER,QUEUE)
    st, recipient = call(project,st,0x8040CC60)
    assert recipient==NOTIFY
    # Same pointer as the separately verified AF init store at 0x8037e14c.
    put(st,0x80C17E00,recipient)
    st,_ = call(project,st,0x8042DCD0,recipient)
    assert get(st,0x80C6AAEC)==NOTIFY and get(st,0x80C6AAF4)==COMPLETE
    return st


def replay_commands(project,angr):
    def notify(st):
        record(st,"notifications",num(st,st.regs.a0))
    def setter_return(st):
        st.globals["setter_result"] = num(st,st.regs.v0)
    def send_return(st):
        st.globals["queue_wrapper_return"] = num(st,st.regs.v0)

    rows = []
    for name, setup, steps in CASES:
        inputs = SETUP | setup
        st = fixture(project,angr,inputs)
        st, af = call(project,st,AF_GET)
        for address in (NOTIFY,COMPLETE):
            st.inspect.b("instruction",when=angr.BP_BEFORE,instruction=address,action=notify)
        st.inspect.b("instruction",when=angr.BP_BEFORE,instruction=DISPATCH_RETURN,action=setter_return)
        if "queue_send_result" in inputs:
            st.globals["queue_send_result"] = inputs["queue_send_result"]
            for address in (SEARCH_SEND_RETURN,STOP_SEND_RETURN):
                st.inspect.b("instruction",when=angr.BP_BEFORE,instruction=address,action=send_return)
        observations = []
        for action,*args in steps:
            row = dict(action=action)
            if action == "drive":
                mode,wait,delivery,link_status,_ = args
                st.globals["delivery"],st.globals["link_result"] = delivery,link_status
                st.globals["wait_count"],st.globals["messages"],st.globals["link"] = 0,(),()
                st.globals["worker_result"] = None
                st,returned = call(project,st,DRIVE,mode,wait,0x12,0x3456,0x12345678)
                pending = SEARCH_PENDING if mode==0 else STOP_PENDING
                row.update(mode=mode,wait_for_motion=wait,worker_delivery_wait=delivery,outer_return=returned,
                           setter_return=st.globals.pop("setter_result"),queue_message=list(st.globals["messages"]),
                           waits=st.globals["wait_count"],worker_result=st.globals["worker_result"],
                           worker_pending=get(st,pending,1),link=list(st.globals["link"]))
                if "queue_wrapper_return" in st.globals:
                    row["queue_wrapper_return"] = st.globals.pop("queue_wrapper_return")
            elif action == "poll":
                if args[0] is not None:
                    put(st,VDRC,args[0],1)
                    put(st,VD_OK,args[1],1)
                st,_ = call(project,st,CALLBACK)
            elif action == "regular-failure":
                st.globals["link_result"],st.globals["link"] = 4,()
                st,result = call(project,st,SINGLE)
                row.update(result=result,link=list(st.globals["link"]))
            else:
                assert action=="reset"
                st,_ = call(project,st,RESET)
                row.update(communications_state=get(st,COMM_STATE,1),map_ready=get(st,MAP_READY,1))
            row.update(cached_motion=get(st,VDRC,1),vd_validity=get(st,VD_OK,1),
                       motion_check_state=get(st,STATE,1),start_count=get(st,COUNT),
                       af_complete=get(st,AF_DONE,1),capture_phase=get(st,CAPTURE_PHASE),
                       notifications=list(st.globals.pop("notifications",())))
            observations.append(row)
        rows.append(dict(name=name,setup=inputs,af_enable=af,steps=observations))
    return rows


def replay_waits(project,angr):
    rows = []
    for name,initial,samples in WAITS:
        st = make_state(project,angr)
        put(st,VDRC,initial[0],1)
        put(st,VD_OK,initial[1],1)
        st.globals["samples"] = samples
        st.regs.pc,st.regs.ra = WAIT_STOP,RETURN_PC
        def stop(state):
            return state.addr==RETURN_PC or (state.addr==0x8042E4D4 and state.globals.get("wait_count",0)==len(samples)
                                             and name=="nonzero-through-bound")
        sim = project.factory.simgr(st,save_unconstrained=True)
        sim.explore(find=stop,n=100)
        assert len(sim.found)==1 and not sim.active and not sim.errored and not sim.unconstrained, sim.errored
        st = sim.found[0]
        rows.append(dict(name=name,initial=list(initial),samples=[list(x) for x in samples],
                         waits=st.globals.get("wait_count",0),returned=int(st.addr==RETURN_PC),stop_pc=hex(st.addr)))
    return rows


def replay_aborts(project,angr):
    rows = []
    for name,entry,active,sleeping,bk,status in ABORTS:
        st = make_state(project,angr)
        for address,value in ((SEQ,active),(SLEEPING,sleeping),(BK_CONTROL,bk),(BK_CANCEL,0),
                              (STOP_COMMAND,0),(CAF_ENABLED,1),(CAF_QUIT,0),(STOP_RELEASE,0)):
            put(st,address,value,1)
        put(st,0x8012D908,EVENT_HANDLE)
        st.globals["event_status"] = status
        if entry=="notify":
            st,result = call(project,st,AF_COMMAND,0xE0002,0)
            assert result==1
        else:
            st,_ = call(project,st,EXIT_WAIT)
        rows.append(dict(name=name,entry=entry,sequence=active,sleeping=sleeping,bk_control=bk,
                         events=list(st.globals.get("caf_events",())),stop_command=get(st,STOP_COMMAND,1),
                         stop_release_after=get(st,STOP_RELEASE,1),enable_caf=get(st,CAF_ENABLED,1),
                         quit_caf=get(st,CAF_QUIT,1),bk_cancel=get(st,BK_CANCEL,1)))
    return rows


def replay(elf):
    if not __debug__:
        raise RuntimeError("replay requires assertions")
    import angr
    project = load_project(elf)
    worker = load_project(elf)
    install(project,worker,angr)
    commands = replay_commands(project,angr)
    waits = replay_waits(project,angr)
    aborts = replay_aborts(project,angr)
    report = dict(reference(),command_cases=commands,wait_cases=waits,abort_cases=aborts,
                  engine=f"angr {angr.__version__} / VEX")
    expected = reference()
    for actual, want in zip(commands,expected["command_cases"],strict=True):
        assert actual==want, (actual["name"],[(a,b) for a,b in zip(actual["steps"],want["steps"],strict=True) if a!=b])
    assert aborts==expected["abort_cases"], (aborts,expected["abort_cases"])
    validate_report(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf",type=Path)
    parser.add_argument("--output",required=True,type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error("replay requires assertions")
    if lexists(args.output):
        parser.error("output must not exist")
    report = replay(args.elf)
    with args.output.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(report,stream,indent=2)
        stream.write("\n")
    print(f"PASS {len(report['command_cases'])} native AF command/completion cases, "
          f"{len(report['wait_cases'])} focus-stop waits and {len(report['abort_cases'])} sequence abort/wait cases")


if __name__=="__main__":
    main()

