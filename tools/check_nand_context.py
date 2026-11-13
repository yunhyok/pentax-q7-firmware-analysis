"""Replay two distinct Q7 context/discovery experiments; no camera access."""
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
from contextlib import contextmanager
from os.path import lexists
import argparse,importlib,importlib.abc,importlib.util,json,struct,sys

SHA='8a928b574623c28624127501526d8496a98a42eac3d843def6d3b5ceb074ff3b'
ELF_SHA256='a973912dbce5c8e09422c0009892dd47e1d7088e8bd8c9020f2a9c8804149796'
SOURCE_PINS={'build_analysis_elf': '2dae569e60f7f46c101341b44e87d7a08c230d9fa81ef517b2f88c64d6db557b', 'check_burn_storage': 'c76aa266afff9060d0b1cff4810b555f8aafe0dbb6623b8a191e00b1ff4e5867', 'check_isp_registers': 'f04d12f97d55624ffab5fa59eddf8bce8b2900d7ef3127bd30761ae7d074cf92', 'check_main_burn': '047efc4e813360b224e86a545292079f74f7f3d09353f4ff7fd7c8fe6ee22d94', 'check_nand_boot_read': 'b66c5e588012af53cdc813b93cf5c6fd9d12c4fbcb6458e74b3545fffd32977d', 'check_nand_headers': '791cefee6157368f610edf33ca8d10c733f6ef1167b83441adf00524ab43fd5b', 'check_q7_portability': '63d52486e6979a15520e97cf33c003f897dae7fbcce4dde08011dce265706af7', 'decode_segments': '050993664b956416f2d85a9dc98cdfa45646fb0a2834018217e41f3e5629220a', 'inspect_q7': '3e8df227d9bf96c6b2bdbd20433e2c80a1d80019d05c0778d978736c606bc2b8', 'pentax_lz': '5a8a60bdbaf7be7c5acead0ab04877b93a3c6e753e8b8f332281974f36c3b6bf', 'q7_symbols': '2b1e228deee232cc7b78ed347cf7319bed711ce1e54dc1bbfc1e63de4e3f0ec7'}
CASE_SHA256={'context': 'f0f4609458ecd5672c06d32283126e8436098287f2238048897e203bab43bcd2', 'discovery': '4afea405404e982c96da0b1c3f5e35c4fc7909d6470b4b47d716f520863c42e7'}

FOCUSED_SOURCE=[{'address': '0x80003c78', 'size': 44, 'sha256': 'c6e18d2e82cdaffb31906d8b2368ba91d14e288ca72960014e110c7ecfdf90a2'}, {'address': '0x80003d9c', 'size': 8, 'sha256': '5ce5ad86d452c4d2422bd63e15223d5d6b3dfb77f224a88c1f476e9fb34e359d'}, {'address': '0x800099fc', 'size': 96, 'sha256': '9cfc171435b6937ed3ee36e270d2d0c7c348856c20a3a6f9cd8efde5db99aced'}, {'address': '0x8000c2b4', 'size': 516, 'sha256': '583ea853ffb2cb4982f128cd2bce5d90f0d9db86d4ff3baa4962c2e7a37ff643'}, {'address': '0x8000c598', 'size': 120, 'sha256': '2a87c5fcd9fe3510d979a9985eb7cfa9d20ab839d9264f015f50b447f44464fd'}, {'address': '0x8000f524', 'size': 40, 'sha256': 'eb3a2d9db78b3c93637b32d1f79e0aaff4157345a3500bf9b3b871faf7260763'}, {'address': '0x8000f598', 'size': 752, 'sha256': 'cddcba1df3c358e7fd30df43d25b8d65c17558ac70a1d05845afde92822ea6e1'}, {'address': '0x8004f400', 'size': 160, 'sha256': 'f2bb5a26d967a3ffaac2506b1ee2cf8b1130c33e653dcc358777808db724e7b6'}, {'address': '0x8004f658', 'size': 92, 'sha256': 'd89edab3197494f68b91c51029431479d1e6e42c9968fe23101b2dfd173a490c'}, {'address': '0x8004fc94', 'size': 1388, 'sha256': '08c39096dffdadc089904df60b00102a3e955f3021a0678fb318cf695de85250'}, {'address': '0x8005072c', 'size': 36, 'sha256': '92a67ed4492add3e06aad687616b5556cefbdaf4a0de04e3aecc81b824d137d9'}, {'address': '0x80050cfc', 'size': 196, 'sha256': '428491312ccc80646096a922c527f2d9c259f8e40d00920af7a9cbe47428b721'}, {'address': '0x80051204', 'size': 32, 'sha256': '9c57a4e7f88dd2ab195b8ec3e778d1afa5fe114f30ead2b21ca9e439d7559b00'}, {'address': '0x80051288', 'size': 28, 'sha256': 'dc5eed702368e1d4e9105d5fcd5379e203e9a52bbeae406cf2e9df401643496a'}, {'address': '0x80053124', 'size': 3404, 'sha256': '05ed3abca064e3f6aeb652959b5892ed29927d593a62cb8c84ec54d61cbbb70c'}, {'address': '0x80053e70', 'size': 248, 'sha256': '8a444636faf7b94af640164c1df5bc726d2ac4adef9dbc16ee6bbdfba6f0c9ed'}, {'address': '0x80055410', 'size': 184, 'sha256': 'f7131d4ac79240cebecc4fea986191ca318dc94969035d8587592f872c1677d2'}, {'address': '0x800554c8', 'size': 108, 'sha256': '3846fb09a0513e7eb4be3cc4914b287e073f7d81f5c4eec3451810b93b7ae14a'}, {'address': '0x80055534', 'size': 392, 'sha256': '0f41c226a4e825d2a1f1e88a715b679f8ac0a4f983115b6e2593a163658bd556'}, {'address': '0x800556bc', 'size': 896, 'sha256': '1420f37ad85c1459e9ff8c50fca4f923bd571e8065dfd4313c37175595bc356d'}, {'address': '0x80055a3c', 'size': 352, 'sha256': '8a5c3ccbccc3b7d1da9b3914151c61fa2b5909f2e1268d9a344c7f42f321e9a5'}, {'address': '0x80055b9c', 'size': 184, 'sha256': '9e11c7cb8cf4d8d3c2ef24264eed7b731ec9a8b68619c6e3d8088bc5a519591f'}, {'address': '0x80055c54', 'size': 148, 'sha256': 'eac6ea72b2167df476bbfe69417ace0dd9e829e725b226d7645e885d23f99421'}, {'address': '0x80055f20', 'size': 1324, 'sha256': 'f7ab7f95393a4ea40ebd5d823a09c826b094bc92ef29f5c20c9cdf16f696ae7b'}, {'address': '0x80056510', 'size': 24, 'sha256': 'db88ca01b975e0dcd2060a4de9b9792895880d281ba8ca5bc8dc539051dfd70d'}, {'address': '0x800599a0', 'size': 84, 'sha256': 'b5c1c1722de5603de3544fa46fb1f7540a299ec8c86eedb4e0a5da3786f58f6d'}, {'address': '0x800631d0', 'size': 12, 'sha256': '15ec7bf0b50732b49f8228e07d24365338f9e3ab994b00af08e5a3bffe55fd8b'}, {'address': '0x80063754', 'size': 96, 'sha256': 'fd8d64813d2f32570b0afd240158100adffde6be27f3a370b52363d78e849153'}, {'address': '0x8006423c', 'size': 520, 'sha256': '94e9b58a4f9931a5722b1a9117b93529aeecd52741e8a1b201cf0b73e8a3c913'}, {'address': '0x800643dc', 'size': 36, 'sha256': 'f6a8fc5159fd1c755c316bf93aa2849756554c75ab758d71a83fad14a17cb1d4'}, {'address': '0x8006444c', 'size': 8, 'sha256': '89c6f1f94ee704e19d46a68511eb96882092f79b9f2b4a29f02765af1b34ee59'}, {'address': '0x80066b2c', 'size': 168, 'sha256': '76815990b3bf6d6c140ea4240cb6a90029669c5fabc1c5752bd0da774306a627'}, {'address': '0x80067700', 'size': 56, 'sha256': 'c2d83767793fa790ea2847ca3dda66c9c9485ed7aa5c79762dab83ea6b61214e'}, {'address': '0x800768b4', 'size': 36, 'sha256': '710282eaae5536cd0b6b5bfec5b2438bdab6f773191c832a3f0fffeeedaff9b8'}, {'address': '0x80076bfc', 'size': 36, 'sha256': '77fe581c85b7986ed1c3bb5cc7d15efac9e8279a0a1ed29b9ecbc4c1cabcdaa9'}, {'address': '0x80076d40', 'size': 36, 'sha256': '4ae477fe3f3b8dcef13438e68ae5735b8a19cbbde72e68229f5814690bbdc9cb'}, {'address': '0x8007aed4', 'size': 36, 'sha256': '4e4c833a50262e3ebb8bf1eafece515c32daa170a189db55d1f4d69c4d4c3c23'}, {'address': '0x8007b5c8', 'size': 36, 'sha256': '05896c32d283f9e1655e8ac5d45fa76691561c5615715283fb074d11f2a56346'}, {'address': '0x8007d81c', 'size': 20, 'sha256': '4aad244c38e951e04b329b464b0f12b7416adb7b293f37fb030fc307960da518'}, {'address': '0x8007e1ac', 'size': 228, 'sha256': '35e27f46315f693d3b5964e8ffba050a882f0b244897d553e7f7c3c6640c3e68'}, {'address': '0x80082d8c', 'size': 172, 'sha256': '07121662fdb24ce20d30ac48574ee6d22ccc39c15706b6857fc6b34b4327f105'}, {'address': '0x80084a58', 'size': 360, 'sha256': '6957a0f6111f86a7e27e030ce783fc51c07fad6800e0a4b730489b7c44dbb6f2'}, {'address': '0x80084bc0', 'size': 2104, 'sha256': '1151348da86ded9853102cf247f067f6593267a4b746d3e2cfd42da7f8ac4169'}, {'address': '0x80084f68', 'size': 32, 'sha256': '09b85e8cdc3a2708673bf7ea2938b3c648cd3335ac0d2cadf92dac3da80dfd84'}, {'address': '0x8008c14c', 'size': 4, 'sha256': 'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119'}, {'address': '0x8008ce5c', 'size': 80, 'sha256': '75bdcaf1540ac552d856c44604b652901ce9d6e80a0647725bce35a9187ae02f'}, {'address': '0x800e79b8', 'size': 164, 'sha256': '2435b6edda23918266f8919e19bfbf0ddca938840c371853597abde9c608b5b9'}, {'address': '0x800e7d8c', 'size': 160, 'sha256': '18122479569946e36a47c64627c446ad56f456c5c3d99f9854683815cf4fd1b8'}, {'address': '0x800e84a8', 'size': 60, 'sha256': 'badc227009d64f6bb267125636af3ad2b33491f8c8e28b9f8db591b8671abfad'}, {'address': '0x800ecde8', 'size': 120, 'sha256': '003cdf196fb7910ee2abdfc880b665c3afd6d3df139fe9e5a08e3e7fab4792ad'}, {'address': '0x800ed240', 'size': 196, 'sha256': 'e8f36a415b4c59359520e3e5ec13fa3ef8fbd2db62a87af9bea325f875a4ff16'}, {'address': '0x800f49cc', 'size': 44, 'sha256': '3547db7c1856ad75c5cf793aab92e4be467fbcc0f14dfb6cc6256ff21b15f3b0'}, {'address': '0x800f4b04', 'size': 20, 'sha256': '81eb04e6d7bf7db25d8663a757bd1166ac4ed03a6888bfcb871ec455fba5a2bf'}, {'address': '0x800f4cf0', 'size': 292, 'sha256': '479ee32944d392e3ec3e47eb1091ef1dcce791ff23ef76a64ac07fb30ea4a946'}, {'address': '0x800f7b88', 'size': 4, 'sha256': 'e1e58d88a834a01bc48b5009349c61617fd8fb0e38e053a4748c2d16fd2caa89'}, {'address': '0x800f7c2c', 'size': 4, 'sha256': '31d9b816a9814589277a7c2e9f20fcfb096dcb32037b4048ff6e8bc35197332e'}, {'address': '0x805e5374', 'size': 80, 'sha256': '94747d76ad95da9e753b793c06daec0a600a5e36fcc67c3ed4b9bcf4e4fb29e3'}, {'address': '0x806000f4', 'size': 196, 'sha256': 'a928fcc2f76c4c9b0a89fe850baa93e936b7fb7a8fe0913eb6ee0a1717490647'}]
REPORT_SHA256='839dfbd595270d08a1ad772d9325b5a48fe98b23819ec3546e67c35aa3b79757'

def canonical(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()

@contextmanager
def pinned_dependencies(tools_dir=None):
    """Verify every project source first, then compile those exact bytes without pyc."""
    root=Path(tools_dir) if tools_dir is not None else Path(__file__).resolve().parent
    sources={}
    for name,expected in SOURCE_PINS.items():
        path=root/(name+'.py')
        raw=path.read_bytes()
        if sha256(raw).hexdigest()!=expected:raise ValueError('source pin mismatch: '+name)
        sources[name]=(path,raw)
    class Loader(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if fullname in sources:return importlib.util.spec_from_loader(fullname,self,origin=str(sources[fullname][0]))
            return None
        def create_module(self,spec):return None
        def exec_module(self,module):
            path,raw=sources[module.__name__]
            module.__file__=str(path)
            exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
    sentinel=object();previous={name:sys.modules.pop(name,sentinel) for name in sources}
    loader=Loader();sys.meta_path.insert(0,loader)
    try:
        yield {name:importlib.import_module(name) for name in sources}
    finally:
        sys.meta_path.remove(loader)
        for name,old in previous.items():
            sys.modules.pop(name,None)
            if old is not sentinel:sys.modules[name]=old

def source_evidence(raw,elf,mods):
    layout,_=mods['inspect_q7'].parse_elf(elf,0)
    def loaded(va,size):
        seg=next(s for s in layout['segments'] if s['type']==1 and s['virtual_address']<=va and va+size<=s['virtual_address']+s['file_size'])
        off=seg['file_offset']+va-seg['virtual_address']
        return elf[off:off+size],off
    plain=[]
    for original,va,size in mods['build_analysis_elf'].PLAIN:
        code=raw[original:original+size];analysis,off=loaded(va,size)
        assert code==analysis and len(code)==size
        plain.append(dict(virtual_address=hex(va),size=size,original_file_offset=hex(original),analysis_elf_offset=hex(off),sha256=sha256(code).hexdigest()))
    manifest,segments=mods['decode_segments'].inspect(raw)
    e05=next(s for s in manifest['segments'] if s['name'].startswith('E05'))
    code=segments[e05['name']];analysis,off=loaded(e05['virtual_address'],len(code))
    assert code==analysis and e05['decoded_sha256']=='a411eecc87e46c88cd58548fdd677a20419494110b2c1b19bf1852ad4bfa78b2'
    focused=[]
    for r in FOCUSED_SOURCE:
        selected,selected_off=loaded(int(r['address'],16),r['size'])
        assert sha256(selected).hexdigest()==r['sha256']
        focused.append(dict(r,analysis_elf_offset=hex(selected_off)))
    package=raw[0x1000c0:0x1004c0]
    assert sha256(package).hexdigest()=='a13cfeb149310c4f692811780e98581dda9b713aef5ec3ea8b3fbacf6a6da623'
    words={hex(o):hex(struct.unpack_from('<I',package,o)[0]) for o in (0x14,0x200,0x214,0x220,0x230,0x310,0x314,0x3a8,0x3ac)}
    return dict(project_source_sha256=SOURCE_PINS,plain_segments=plain,decoded_e05=dict(virtual_address=hex(e05['virtual_address']),size=len(code),sha256=e05['decoded_sha256'],analysis_elf_offset=hex(off)),focused_ranges=focused,package_template=dict(original_file_offset='0x1000c0',size=0x400,sha256=sha256(package).hexdigest(),little_endian_words=words,actual_installed_media=False),boundary='Original plain regions and freshly decoded entire E05 compared before engine import. Focused range digests checked within those regions. No firmware bytes included.')

def bind_modules(mods):
    global n,m,c,arguments,num,u32,put_u32,read_bytes,load_project,STACK_TOP,RETURN_PC,new_state,guard
    n,m,c=(mods[k] for k in ('check_nand_boot_read','check_main_burn','check_nand_headers'))
    b=mods['check_burn_storage'];arguments,num,u32,put_u32,read_bytes=(getattr(b,k) for k in ('arguments','num','u32','put_u32','read_bytes'))
    i=mods['check_isp_registers'];load_project,STACK_TOP,RETURN_PC=i.load_project,i.STACK_TOP,i.RETURN_PC
    q=mods['check_q7_portability'];new_state,guard=q.new_state,q.guard

CONSTRUCTOR=0x80084BC0
GLOBAL,HEAP,HEAP_END=0x8008C14C,0x24500000,0x24580000
PUBLISH_NEXT,PARTITION_DEREF=0x80084C44,0x80084AC0


def walk(p,st,target,steps=20000):
    sim=p.factory.simgr(st,save_unconstrained=True)
    sim.explore(find=target,avoid=(m.RETURN_PC,m.BURN_NAND,m.HOST_ACK),n=steps)
    assert len(sim.found)==1 and not(sim.active or sim.errored or sim.unconstrained or sim.deadended or sim.avoid),(sim,sim.errored)
    return sim.found[0]


def run_context(raw,elf,angr):
    p=load_project(elf);saved=[];supplied=[];writes=[];reads=[]
    old_new,old_guard,old_advance=m.new_state,m.guard,c.advance
    def create(project,engine):
        st=old_new(project,engine)
        def change_argument(s):
            addr=num(s,s.regs.sp)+0x18
            assert u32(s,addr)==0x80000000 and not supplied
            s.memory.store(addr,(0).to_bytes(4,'little'),size=4)
            supplied.append(dict(pc='0x80067700',stack_address=hex(addr),argument=7,before='0x80000000',after=0))
        def watch_write(s):
            a=s.inspect.attrs;addr=num(s,a.mem_write_address)
            if addr in (GLOBAL,HEAP,HEAP+0x80,HEAP+0x81,m.HANDLE+0xBF4):
                writes.append(dict(address=hex(addr),size=num(s,a.mem_write_length),value=num(s,a.mem_write_expr),vex_context_pc=hex(num(s,s.scratch.ins_addr)),state_pc=hex(s.addr)))
        def watch_read(s):
            a=s.inspect.attrs;addr=num(s,a.mem_read_address)
            if addr in (GLOBAL,m.MEDIA_INFO+0xC84,m.MEDIA_INFO+0xC88,m.MEDIA_INFO+0xC8C):
                reads.append(dict(address=hex(addr),size=num(s,a.mem_read_length),value=num(s,a.mem_read_expr),vex_context_pc=hex(num(s,s.scratch.ins_addr)),state_pc=hex(s.addr)))
        st.inspect.b('instruction',when=angr.BP_BEFORE,instruction=0x80067700,action=change_argument)
        st.inspect.b('mem_write',when=angr.BP_BEFORE,action=watch_write)
        st.inspect.b('mem_read',when=angr.BP_AFTER,action=watch_read)
        return st
    def extend_guard(st,engine,ram,readonly=()):
        return old_guard(st,engine,(*ram,(GLOBAL,GLOBAL+4),(HEAP,HEAP_END)),readonly)
    class Captured(Exception):pass
    def capture(project,state,target,engine,*,steps):
        if target==n.RETRY:
            saved.append(walk(project,state,CONSTRUCTOR,steps))
            raise Captured()
        return old_advance(project,state,target,engine,steps=steps)
    spec=dict(name='nonsentinel-stride256',fourth=1,first_word=0x123,second_word=0,redirect=False,fail=False)
    with patch.object(m,'new_state',create),patch.object(m,'guard',extend_guard),patch.object(c,'advance',capture):
        try:n.run_header_case(p,angr,raw[m.UPDATE_HEADER_OFFSET:m.UPDATE_HEADER_OFFSET+m.UPDATE_HEADER_SIZE],spec)
        except Captured:pass
    assert len(saved)==1 and len(supplied)==1
    st=saved[0];initial_events=len(list(st.history.bbl_addrs))
    assert arguments(st)[:4]==[m.HANDLE,GLOBAL,0,1] and num(st,st.regs.ra)==0x800643FC
    assert u32(st,GLOBAL)==0 and u32(st,m.HANDLE+0xC10)==0x123
    assert u32(st,m.HANDLE+0x1D4)==0
    assert u32(st,m.MEDIA_INFO+0xC84)==0 and u32(st,m.MEDIA_INFO+0xC8C)==24
    allocations=[];api_events=[];cursor=HEAP
    class Allocation(angr.SimProcedure):
        def run(self,*,calloc):
            nonlocal cursor
            a=arguments(self.state);ra=num(self.state,self.state.regs.ra)
            if calloc:
                assert a[0]==0 and a[3]==0 and a[4]==0x8008EF6C
                assert (a[1],a[2],a[5],ra) in ((1,0x94,0x1331,0x80084D18),(4,4,0x1393,0x80084E8C))
                size=a[1]*a[2]
            else:
                assert a[0]==0 and a[2]==0 and a[3]==0x8008EF6C
                assert (a[1],a[4],ra) in ((16384,0x1385,0x80084E20),(16000,0x138A,0x80084E44),(16,0x138E,0x80084E68),(131072,0xC8F,0x8007E288))
                size=a[1]
            address=cursor;cursor=(cursor+size+15)&~15
            assert cursor<=HEAP_END
            self.state.memory.store(address,bytes(size),size=size)
            allocations.append(dict(api='PoolCallocEx' if calloc else 'PoolAllocEx',address=hex(address),size=size,arguments=[hex(v) for v in a[:6 if calloc else 5]],return_address=hex(ra),supplied_zeroed=True))
            return address
    class Api(angr.SimProcedure):
        def run(self,*,api):
            a=arguments(self.state);ra=num(self.state,self.state.regs.ra)
            if api==0x800CE6D4:assert a[:3]==[HEAP+0x64,0x8008F854,1] and ra==0x80084D30;arity=3;result=0
            elif api==0x800CEF4C:assert a[:2]==[HEAP+0x64,0xFFFFFFFF];arity=2;result=0
            elif api==0x800D0264:assert a[0]==HEAP+0x64;arity=1;result=0
            else:assert api==0x800D9AC8;arity=0;result=1
            api_events.append(dict(api=hex(api),arguments=[hex(v) for v in a[:arity]],return_address=hex(ra),result=result))
            return result
    p.hook(0x8000C2B4,Allocation(num_args=0,calloc=True),replace=True)
    p.hook(0x8000BF28,Allocation(num_args=0,calloc=False),replace=True)
    for api in (0x800CE6D4,0x800CEF4C,0x800D0264,0x800D9AC8):p.hook(api,Api(num_args=0,api=api),replace=True)
    registered=walk(p,st,PUBLISH_NEXT)
    assert u32(registered,GLOBAL)==HEAP and u32(registered,HEAP)==1
    assert u32(registered,m.HANDLE+0xBF4)==1024000
    assert [u32(registered,HEAP+o) for o in (4,8,12,16,20,24)]==[4000,4096,4,256,1000,1024]
    publish=dict(stop_before=hex(registered.addr),context_pointer=hex(u32(registered,GLOBAL)),context_kind=u32(registered,HEAP),reference_byte=read_bytes(registered,HEAP+0x80,1).hex(),
        context_fields={hex(o):u32(registered,HEAP+o) for o in (0,4,8,12,16,20,24,28,32,36,40,44,48,96)},
        capacity=u32(registered,m.HANDLE+0xBF4),constructor_vex_events=len(list(registered.history.bbl_addrs))-initial_events)
    print('Original context allocation/kind/global publication PASS',flush=True)
    stopped=walk(p,registered,PARTITION_DEREF)
    assert num(stopped,stopped.regs.t4)==0 and u32(stopped,m.MEDIA_INFO+0xC84)==0
    assert read_bytes(stopped,HEAP+0x80,1)==b'\1'
    history=list(stopped.history.bbl_addrs)[initial_events:]
    assert 0x80084558 not in history and m.NAND_EX not in history
    assert len(allocations)==7 and sum(e['api']=='0x800d9ac8' for e in api_events)==8
    assert [e['value'] for e in writes if e['address']==hex(GLOBAL)]==[HEAP]
    assert [e['value'] for e in writes if e['address']==hex(HEAP) and e['size']==4]==[1]
    assert [e['value'] for e in writes if e['address']==hex(HEAP+0x80)]==[0,1]
    assert [e['value'] for e in writes if e['address']==hex(HEAP+0x81)]==[0]
    result=dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,engine=f'angr {angr.__version__} / original MIPS32LE / VEX',
        public_checker_sha256=SOURCE_PINS['check_nand_boot_read'],
        scope='Controlled FileX argument7 changed at original entry, then original request4 and TlDriverInit; no supplied hNandTlInfo pointer or kind store.',
        runtime='Pinned analysis ELF RWX and shared synthetic prefix RAM/globals. Guard adds write access only to hNandTlInfo and synthetic heap24500000..24580000. Native null config dereference is not allowed.',
        supplied_filex_argument=supplied,prefix=dict(header=spec,existing_models=m.NATIVE_OPEN_MODELS,synthetic_id='ecdc000100000000',
            header_word_200='0x123',modeled_header_allocation_and_release_request=True,actual_free=False,constructor_entry=hex(CONSTRUCTOR),constructor_arguments=[hex(x) for x in arguments(st)[:4]],return_address=hex(num(st,st.regs.ra)),prefix_vex_events=initial_events),
        initial_media_record=dict(pointer=hex(m.MEDIA_INFO),kind=1,c84=0,c88=0,c8c=24),
        allocations=allocations,api_models=api_events,publication=publish,
        final=dict(stop_before=hex(stopped.addr),reason='Original media-info+c84 is zero; next original lw uses address0x220, outside guarded memory. No replacement config pointer or data supplied.',
            next_instruction='lw t6,0x220(t4)',t4=0,next_read_address='0x220',context_pointer=hex(u32(stopped,GLOBAL)),context_kind=u32(stopped,HEAP),reference_byte=1,
            constructor_vex_events=len(history),request5_reached=False,nand_ex_reached=False),
        writes=writes,reads=reads,
        limitations=['FileX argument7=0 is a deliberate counterfactual control, not the original Burn sentinel.','NAND ID/header and allocations/API status are supplied models; not camera observations.',
            'PoolAllocEx buffers are supplied zeroed too; physical allocator contents unobserved.','No native semaphore or counter implementation. Counter model returns1 eight times.',
            'Context is published but constructor has not returned successfully. No natural request5 or NAND Ex response reached.',
            'Current Burn flags2 skip media-config producer. Full discovery would require additional actual media response evidence.'])
    return result


ENTRY,INIT,NAND=0x800f4de8,0x80055f20,0x80053124
MUTEX,RECORD,HEADER=0x24600000,0x24601000,0x24602000
REGISTRY,ECC=0x800631d0,0x80059a58

def advance(p,st,target,*,resume=False):
    sim=p.factory.simgr(st,save_unconstrained=True)
    if resume:sim.step()
    sim.explore(find=target,avoid=RETURN_PC if target!=RETURN_PC else (),n=2500)
    assert len(sim.found)==1 and not(sim.active or sim.errored or sim.unconstrained or sim.deadended or sim.avoid),(sim,sim.errored)
    return sim.found[0]

def request(st):
    args=arguments(st)+[u32(st,num(st,st.regs.sp)+28)]
    return dict(pc=hex(st.addr),return_address=hex(num(st,st.regs.ra)),arguments=[hex(x) for x in args],vex_events=len(list(st.history.bbl_addrs)))

def run_discovery_case(angr,elf,name):
    p=load_project(elf)
    allocations=[];api=[];writes=[];io=[];entries=[];reads=[]
    payload=bytearray(0x400) if name=='all-zero-control' else bytearray([0xa5])*0x400
    struct.pack_into('<I',payload,0x14,0)
    if name!='all-zero-control':
        for off,value in ((0x220,0xdeadbeef),(0x3a8,0x12345678),(0x3ac,0x76543210)):
            struct.pack_into('<I',payload,off,value)
    class Model(angr.SimProcedure):
        def run(self,*,address):
            st=self.state;args=arguments(st);ra=num(st,st.regs.ra);result=0
            if address==0x8000c2b4:
                size=args[1]*args[2]
                result={0x2c:MUTEX,0xc90:RECORD}[size]
                assert args[:4]==[0,1,size,0]
                assert ra=={0x2c:0x80056194,0xc90:0x80055fdc}[size]
                st.memory.store(result,bytes(size),size=size)
                allocations.append(dict(api=hex(address),arguments=[hex(x) for x in args[:6]],size=size,address=hex(result),return_address=hex(ra),supplied_zeroed=True))
            elif address==0x8000bf28:
                assert args[:5]==[0,0x400,0,0x80063a88,0x3e1] and ra==0x8005635c
                result=HEADER;st.memory.store(result,bytes(0x400),size=0x400)
                allocations.append(dict(api=hex(address),arguments=[hex(x) for x in args[:5]],size=0x400,address=hex(result),return_address=hex(ra),supplied_zeroed=True))
            elif address==0x800cdb00:assert args[:3]==[MUTEX,0x80063b60,1]
            elif address==0x800cbee4:assert args[:2]==[MUTEX,0xffffffff]
            elif address==0x800d193c:assert args[0]==MUTEX
            else:assert address==0x800a14f8
            api.append(dict(address=hex(address),return_address=hex(ra),result=result))
            return result
    class Response(angr.SimProcedure):
        def run(self):
            st=self.state;args=arguments(st);size=u32(st,num(st,st.regs.sp)+28)
            dev,handle,op,pos,count,data,extra=args
            assert (dev,handle,pos)==(1,RECORD+8,0)
            assert num(st,st.regs.ra)==0x80053f0c
            if len(io)==0:
                assert op==2 and (count,extra,size)==(0,0,0)
                supplied=bytes.fromhex('ecdc000100000000');dest=data
            elif len(io)==1:
                assert op==6 and (count,data,size)==(1,0,16)
                supplied=b'\xff'*16;dest=extra
            else:
                assert len(io)==2 and op==4 and (count,data,extra,size)==(2,HEADER,0,0)
                supplied=bytes(payload);dest=data
            st.memory.store(dest,supplied,size=len(supplied))
            io.append(dict(operation=op,position=pos,count=count,status=0,bytes=len(supplied),supplied_sha256=sha256(supplied).hexdigest(),arguments=[hex(x) for x in args+[size]]))
            return 0
    for address in (0x8000c2b4,0x8000bf28,0x800cdb00,0x800cbee4,0x800d193c,0x800a14f8):p.hook(address,Model(num_args=0,address=address))
    st=new_state(p,angr)
    assert read_bytes(st,REGISTRY,12)==bytes(12)
    image=tuple((s.min_addr,s.max_addr+1) for s in p.loader.main_object.segments)
    guard(st,angr,((MUTEX,MUTEX+0x2c),(RECORD,RECORD+0xc90),(HEADER,HEADER+0x400),(REGISTRY,REGISTRY+12),(ECC,ECC+2)),image)
    watched={RECORD,RECORD+0xc20,RECORD+0xc80,RECORD+0xc84,RECORD+0xc88,RECORD+0xc8c,ECC,ECC+1,REGISTRY,REGISTRY+4}
    def write(state):
        a=state.inspect.attrs;addr=num(state,a.mem_write_address)
        if addr in watched:writes.append(dict(pc=hex(num(state,state.scratch.ins_addr)),address=hex(addr),size=num(state,a.mem_write_length),value=num(state,a.mem_write_expr)))
    def read(state):
        a=state.inspect.attrs;addr=num(state,a.mem_read_address)
        if HEADER<=addr<HEADER+0x400:reads.append(dict(pc=hex(num(state,state.scratch.ins_addr)),address=hex(addr),size=num(state,a.mem_read_length),value=num(state,a.mem_read_expr)))
    def enter(state):
        if state.addr==INIT:entries.append(dict(pc=hex(INIT),args=arguments(state)[:2]))
    st.inspect.b('mem_write',when=angr.BP_BEFORE,action=write)
    st.inspect.b('mem_read',when=angr.BP_AFTER,action=read)
    st.inspect.b('instruction',when=angr.BP_BEFORE,instruction=INIT,action=enter)
    st.regs.pc,st.regs.ra,st.regs.a0=ENTRY,RETURN_PC,8
    first=advance(p,st,NAND)
    assert entries==[dict(pc=hex(INIT),args=[1,1])],entries
    first_request=request(first)
    assert u32(first,REGISTRY+4)==RECORD and u32(first,RECORD+0xc84)==0
    p.hook(NAND,Response(num_args=0))
    second=advance(p,first,NAND,resume=True)
    second_request=request(second)
    assert len(io)==1 and u32(second,RECORD+0xc84)==HEADER
    assert u32(second,RECORD+0xc20)==0x105 and read_bytes(second,ECC,2)==b'\x01\x00'
    assert int.from_bytes(read_bytes(second,RECORD+0xc1c,2),'little')==8
    assert u32(second,RECORD+0xc80)==0x800
    assert any(w['pc']=='0x8005635c' and w['address']==hex(RECORD+0xc84) and w['value']==HEADER for w in writes)
    header_boundary=dict(request=second_request,context_config_pointer=hex(u32(second,RECORD+0xc84)),record_c20=hex(u32(second,RECORD+0xc20)),stride_shift=8,record_c80=0x800,ecc_bytes=read_bytes(second,ECC,2).hex(),header_sha256_before_response=sha256(read_bytes(second,HEADER,0x400)).hexdigest())
    final=advance(p,second,RETURN_PC,resume=True)
    assert len(io)==3 and num(final,final.regs.v0)==1 and num(final,final.regs.sp)==STACK_TOP
    assert read_bytes(final,HEADER,0x400)==bytes(payload)
    expected88=payload[0x3a8];expected8c=int.from_bytes(payload[0x3ac:0x3b0],'little')
    assert read_bytes(final,RECORD+0xc88,1)==bytes([expected88]) and u32(final,RECORD+0xc8c)==expected8c
    assert not any(r['address']==hex(HEADER+0x220) for r in reads)
    return dict(name=name,entry='AppFcuMediaInfoInit(8), isolated source-derived selector; AppFcuInit and prior FcuInit not replayed',native_init_entry=entries[0],first_hardware_facing_boundary=first_request,after_supplied_id_boundary=header_boundary,allocations=allocations,api_models=api,io_models=io,native_writes=writes,header_reads=reads,final=dict(return_value=1,vex_events=len(list(final.history.bbl_addrs)),config_pointer=hex(u32(final,RECORD+0xc84)),config_word_220=hex(u32(final,HEADER+0x220)),record_c88=expected88,record_c8c=expected8c,header_sha256=sha256(payload).hexdigest()),limits=['Synthetic ID and header, no camera validity or hardware response.','Whole AppFcuInit/FcuInit, AppFb/FileX and TlDriverInit not replayed.','Allocator and mutex/diagnostic APIs modeled; initial registry from pinned ELF.','No header+220 semantic validity established; producer does not consume it.'])


def replay(firmware,elf):
    if not __debug__:raise RuntimeError('replay requires assertions')
    if sha256(firmware).hexdigest()!=SHA:raise ValueError('expected SHA-pinned Q7 firmware')
    elf_bytes=elf.read_bytes()
    if sha256(elf_bytes).hexdigest()!=ELF_SHA256:raise ValueError('expected SHA-pinned Q7 analysis ELF')
    # CLI replay is serial: dependency modules and inspection hooks are process-global.
    with pinned_dependencies() as mods:
        source=source_evidence(firmware,elf_bytes,mods)
        bind_modules(mods)
        import angr
        context=run_context(firmware,elf,angr)
        discovery=dict(input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,engine=f'angr {angr.__version__} / VEX',cases=[run_discovery_case(angr,elf,name) for name in ('all-zero-control','arbitrary-pattern-control')])
    report=dict(schema_version=1,input_sha256=SHA,analysis_elf_sha256=ELF_SHA256,source=source,context=context,discovery=discovery,
        scope='Two separate controlled experiments, preserving complete accepted records. They do not form one camera boot or FileX initialization sequence.',
        trace_pc_semantics='VEX instruction-context PCs can name a branch for its delay-slot store; exact native addresses require original instruction evidence.',
        limitations=['Context: FileX arg7 changed from 80000000 to0; pointer publication precedes successful initialization; stop before null config dereference80084ac0.',
          'Discovery: isolated AppFcuMediaInfoInit(8), native kind1/flags1; prior AppFcuInit/FcuInit and subsequent constructor/FileX not executed.',
          'Supplied ID, header/spare bytes, statuses, zeroed heaps and synchronization/counter responses are models, not camera observations.',
          'Discovery stops at NAND Ex ABI boundaries before supplying explicit responses. Its low MMIO body is never executed.',
          'No actual media, boot, physical units, controller behavior, firmware write or recovery established.'])
    validate_report(report)
    return report

def validate_report(report):
    if not __debug__:raise RuntimeError('validation requires assertions')
    assert report['schema_version']==1 and report['input_sha256']==SHA and report['analysis_elf_sha256']==ELF_SHA256
    assert report['source']['project_source_sha256']==SOURCE_PINS
    for key,expected in CASE_SHA256.items():assert canonical(report[key])==expected,key+' observations differ'
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
        with args.output.open('x',encoding='utf-8',newline='\n') as f:json.dump(report,f,indent=2);f.write('\n')
    except FileExistsError:ap.error('output appeared while replaying')
    print('PASS distinct context constructor and two media-config response controls')

if __name__=='__main__':main()
