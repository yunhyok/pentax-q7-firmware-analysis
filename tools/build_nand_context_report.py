"""Build the NAND context/discovery report from its pinned JSON, without firmware."""
from pathlib import Path
from hashlib import sha256
from html import escape
import json

ROOT=Path(__file__).resolve().parents[1]
REPORT_SHA256='839dfbd595270d08a1ad772d9325b5a48fe98b23819ec3546e67c35aa3b79757'

def canonical(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()

def rows(items):
    return ''.join('<tr>'+''.join('<td>'+escape(str(v))+'</td>' for v in item)+'</tr>' for item in items)

def main():
    data=json.loads((ROOT/'analysis/nand-context-checks.json').read_bytes())
    if canonical(data)!=REPORT_SHA256:raise ValueError('complete report differs')
    context,discovery=data['context'],data['discovery']
    values=dict(
        allocation_rows=rows((r['api'],r['address'],r['size'],r['return_address']) for r in context['allocations']),
        discovery_rows=rows((r['name'],r['final']['return_value'],r['final']['config_word_220'],hex(r['final']['record_c88']),hex(r['final']['record_c8c']),r['final']['vex_events']) for r in discovery['cases']),
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
