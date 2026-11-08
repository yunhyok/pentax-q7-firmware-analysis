"""Verify rebuild and portability metadata; optionally reproduce original evidence."""
import hashlib
import struct
from build_deep_report import read
from check_isp_registers import ELF_SHA256
from check_q7_portability import validate_report
from check_update_gate import reference as gate_reference
from q7_symbols import SHA
from verify_routing import witnesses, verify_words


def verify(firmware=None, decoded=None):
    rebuild,portability=read('rebuild-evidence.json'),read('portability-evidence.json')
    validate_report(portability['replay'])
    assert rebuild['app_gate']['replay']==gate_reference()
    rt=rebuild['roundtrip']['package_report'];patch=rebuild['patch_experiment']['package_report']
    assert rt['input_sha256']==patch['input_sha256']==SHA
    assert rt['output_sha256']==SHA and rt['byte_identical'] and not rt['patches']
    assert rt['analysis_elf_sha256']==ELF_SHA256
    assert rt['output_size']==patch['output_size']==read('evidence.json')['input_size']
    assert sum(s['blocks'] for s in rt['segment_results'])==448
    assert all(not s['changed_blocks'] for s in rt['segment_results'])
    changed=[(s['name'],b) for s in patch['segment_results'] for b in s['changed_blocks']]
    assert len(changed)==1 and changed[0][0]=='E04' and changed[0][1]['block']==146
    assert patch['patches'][0]['va']==rebuild['patch_experiment']['patch_va']=='0x803f0210'
    assert len(patch['patches'])==1 and rebuild['patch_experiment']['replay_returns']==[0,1]
    for report in (rt,patch):
        for key in ('footer_before','footer_after'):
            footer=report[key]
            assert footer['identifiers']==['ORION','KB538','77690']
            assert footer['stored_sum']==footer['calculated_sum'] and footer['sum_matches']
            assert footer['version_bytes']==[1,1,23,10]
    boot_replay=rebuild['boot_dispatch']['replay']
    assert boot_replay['modified_elf_sha256']==patch['analysis_elf_sha256']
    assert (boot_replay['baseline_return'],boot_replay['modified_return'])==(0,1)
    assert [(c['kind'],c['header_hash_flag'],c['burn_callback']) for c in boot_replay['header_cases']]==[
        (3,0,'0x80012654'),(3,1,'0x80012654'),(8,0,'0x8001e328'),(5,0,'0x80010f18'),(7,0,None)]
    for document in (rebuild,portability):
        assert document['input_sha256']==SHA and document['analysis_elf_sha256']==ELF_SHA256
        assert list(witnesses(document))
        for f in document['selected_functions']+document.get('boot_selected_functions',[]):
            assert f['candidate_end']-f['address']==f['size']>0
            assert not ((f['address']|f['size'])&3)
            assert len(f['sha256'])==64
            assert all(f['address']<=e['site']<f['candidate_end'] for e in f['transfers'])
    status=read('hq-status.json')
    assert status['model']=='Pentax Q7' and status['updated_at'].endswith('+09:00')
    assert set(status['goals'])=={'rebuild','raw_profile','autofocus','ui_port'}
    for goal in status['goals'].values():
        assert all(goal[k] for k in ('status','evidence','gaps','next_actions'))
    if firmware is None: return
    from build_analysis_elf import PLAIN, DECODED
    from inspect_q7 import parse_elf
    from repack_q7 import footer_check
    from trace_q7 import trace, transfer
    assert hashlib.sha256(firmware).hexdigest()==SHA and decoded is not None
    segments=[('E03',va,firmware[o:o+n],o) for o,va,n in PLAIN]
    segments += [(name[:-4],va,decoded[name[:-4]],None) for name,va,_ in DECODED]
    boot,symbols=parse_elf(firmware,0x200)
    assert boot['sha256_referenced_bytes']==rebuild['boot_image']['sha256']
    assert boot['segments']==rebuild['boot_image']['load_segments']
    boot_segments=[('E01',s['virtual_address'],firmware[s['file_offset']:s['file_offset']+s['file_size']],s['file_offset']) for s in boot['segments'] if s['type']==1]
    count=0
    for document in (rebuild,portability):
        words=list(witnesses(document))
        count+=verify_words([w for w in words if w['segment']!='E01'],segments)
        count+=verify_words([w for w in words if w['segment']=='E01'],boot_segments)
        assert trace(firmware,[f['name'] for f in document['selected_functions']],decoded)['functions']==document['selected_functions']
    for w in rebuild['file_evidence']:
        assert struct.unpack_from('<I',firmware,int(w['original_file_offset'],16))[0]==int(w['u32le_word'],16)
    verify_boot_functions(firmware,boot,symbols,rebuild['boot_selected_functions'])
    header=rebuild['boot_dispatch'];off=int(header['header_original_file_offset'],16)
    assert hashlib.sha256(firmware[off:off+header['header_size']]).hexdigest()==header['header_sha256']
    assert footer_check(firmware)==rt['footer_before']==rt['footer_after']
    print(f'Rebuild/AF/UI: {count} VA words, {len(rebuild["file_evidence"])} file words, main and typed E01 functions reproduced')


def verify_boot_functions(firmware,boot,symbols,functions):
    from trace_q7 import transfer
    labels={}
    for s in symbols:
        if s['name']: labels.setdefault(s['value'],[]).append(s['name'])
    for f in functions:
        found=[s for s in symbols if s['name']==f['name'] and s['value']==f['address'] and s['size']==f['size'] and s['type']==2]
        assert found and found[0]['section_index']==f['section_index']
        load=boot['segments'][f['pt_load_index']]
        off=load['file_offset']+f['address']-load['virtual_address']
        assert off==int(f['original_file_offset'],16)
        body=firmware[off:off+f['size']]
        assert hashlib.sha256(body).hexdigest()==f['sha256']
        for offset in f['symbol_table_original_file_offsets']:
            _,va,size,info,_,ndx=struct.unpack_from('<IIIBBH',firmware,int(offset,16))
            assert (va,size,info&15,ndx)==(f['address'],f['size'],2,f['section_index'])
        edges=[]
        for pos in range(0,len(body),4):
            pc=f['address']+pos;word=struct.unpack_from('<I',body,pos)[0];item=transfer(word,pc)
            if item:
                kind,target=item
                if kind=='jump' and f['address']<=target<f['candidate_end']: continue
                edges.append(dict(site=pc,word=f'{word:08x}',kind=kind,target=target,target_names=labels.get(target,[])))
        assert edges==f['transfers']


if __name__=='__main__':
    verify()
    print('Rebuild and AF/UI metadata: PASS')
