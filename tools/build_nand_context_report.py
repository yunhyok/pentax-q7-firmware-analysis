"""Build the NAND context/discovery report from its pinned JSON, without firmware."""
from pathlib import Path
from hashlib import sha256
from html import escape
import json

ROOT=Path(__file__).resolve().parents[1]
REPORT_SHA256='839dfbd595270d08a1ad772d9325b5a48fe98b23819ec3546e67c35aa3b79757'

def canonical(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()

def code(value):
    return '<code>'+escape(str(value))+'</code>'

def main():
    data=json.loads((ROOT/'analysis/nand-context-checks.json').read_bytes())
    if canonical(data)!=REPORT_SHA256:raise ValueError('complete report differs')
    context,discovery,source=data['context'],data['discovery'],data['source']
    pub,final=context['publication'],context['final']
    cases=discovery['cases']
    # Fixed facts written in the template prose and diagrams.
    assert context['supplied_filex_argument']==[{'pc':'0x80067700','stack_address':'0x70000fd0','argument':7,'before':'0x80000000','after':0}]
    assert context['prefix']['header']['fourth']==1 and context['prefix']['constructor_arguments']==['0x24002000','0x8008c14c','0x0','0x1']
    assert pub['context_kind']==1 and pub['stop_before']=='0x80084c44' and pub['reference_byte']=='00'
    assert [pub['context_fields'][k] for k in ('0x0','0x4','0x8','0xc','0x10','0x14','0x18')]==[1,4000,4096,4,256,1000,1024]
    assert pub['capacity']==1024000 and context['initial_media_record']['c88']==0 and context['initial_media_record']['c8c']==24
    assert final['stop_before']=='0x80084ac0' and final['next_read_address']=='0x220' and final['reference_byte']==1
    assert not final['request5_reached'] and not final['nand_ex_reached']
    assert context['allocations'][0]['size']==0x94 and context['allocations'][0]['address']==pub['context_pointer']
    assert sum(1 for a in context['api_models'] if a['api']=='0x800d9ac8' and a['result']==1)==8
    assert any(w['address']=='0x24002bf4' and w['value']==1048576 for w in context['writes'])
    for c in cases:
        b=c['after_supplied_id_boundary']
        assert c['native_init_entry']=={'pc':'0x80055f20','args':[1,1]}
        assert c['first_hardware_facing_boundary']['vex_events']==24 and b['request']['vex_events']==61
        assert (b['record_c20'],b['stride_shift'],b['ecc_bytes'],b['context_config_pointer'])==('0x105',8,'0100','0x24602000')
        assert [a['size'] for a in c['allocations']]==[0x2c,0xc90,0x400] and c['final']['return_value']==1
    pattern=cases[1]['final']
    assert (pattern['config_word_220'],pattern['record_c88'],pattern['record_c8c'])==('0xdeadbeef',0x78,0x76543210)
    pkg=source['package_template']
    assert pkg['original_file_offset']=='0x1000c0' and pkg['size']==1024 and not pkg['actual_installed_media']
    assert pkg['little_endian_words']['0x220']=='0x18000' and pkg['little_endian_words']['0x230']=='0xffffffff'

    def access(kind,r):
        return (f'<tr><th scope="row">{kind}</th><td>{code(r["address"])}</td><td class="n">{r["size"]}</td>'
                f'<td>{code(hex(r["value"]))}</td><td>{code(r["vex_context_pc"])}</td></tr>')
    values=dict(
        allocation_rows=''.join(f'<tr><th scope="row">{escape(r["api"])}</th><td>{code(r["address"])}</td>'
            f'<td class="n">{r["size"]:,}</td><td>{code(r["return_address"])}</td></tr>' for r in context['allocations']),
        context_rows=''.join(f'<tr><th scope="row">{code("+"+k)}</th><td class="n">{pub["context_fields"][k]:,}</td></tr>'
            for k in ('0x0','0x4','0x8','0xc','0x10','0x14','0x18')),
        access_rows=''.join(access('쓰기',w) for w in context['writes'])+''.join(access('읽기',r) for r in context['reads']),
        discovery_rows=''.join(f'<tr><th scope="row">{code(r["name"])}</th><td class="n">{r["final"]["return_value"]}</td>'
            f'<td>{code(r["final"]["config_word_220"])}</td><td>{code(hex(r["final"]["record_c88"]))}</td>'
            f'<td>{code(hex(r["final"]["record_c8c"]))}</td><td class="n">{r["final"]["vex_events"]}</td></tr>' for r in cases),
        package_rows=''.join(f'<tr><th scope="row">{code("+"+k)}</th><td>{code(v)}</td></tr>' for k,v in pkg['little_endian_words'].items()),
        package_sha=pkg['sha256'],
        allocation_count=str(len(context['allocations'])),
        context_pointer=pub['context_pointer'],capacity=f"{pub['capacity']:,}",
        publish_vex=f"{pub['constructor_vex_events']:,}",final_vex=f"{final['constructor_vex_events']:,}",
        first_vex=str(cases[0]['first_hardware_facing_boundary']['vex_events']),
        second_vex=str(cases[0]['after_supplied_id_boundary']['request']['vex_events']),
        config_pointer=cases[0]['final']['config_pointer'],
        source_count=str(len(source['project_source_sha256'])),plain_count=str(len(source['plain_segments'])),
        e05_size=f"{source['decoded_e05']['size']:,}",focused_count=str(len(source['focused_ranges'])),
        firmware_sha=data['input_sha256'],elf_sha=data['analysis_elf_sha256'],
        context_sha=canonical(context),discovery_sha=canonical(discovery),report_sha=REPORT_SHA256)
    page=(ROOT/'analysis/nand-context-template.html').read_text(encoding='utf-8')
    for key,value in values.items():page=page.replace('{{'+key+'}}',value)
    if '{{' in page:raise ValueError('unresolved HTML placeholder')
    output=ROOT/'reports/nand-context.html'
    output.parent.mkdir(exist_ok=True)
    output.write_text(page,encoding='utf-8',newline='\n')
    print('Built reports/nand-context.html')

if __name__=='__main__':main()
