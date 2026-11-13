"""Render the three distinct NAND continuation experiments without firmware or angr."""
from build_deep_report import ROOT, read, esc
from check_nand_boot_read import REPORT_SHA256, validate_report


def main():
    data=read('nand-boot-read-checks.json')
    validate_report(data)
    header_rows=[]
    for row in data['header_information']['cases']:
        info=row.get('information_get')
        if info:
            f=info['fields']; geometry=row['separate_request9']
            cells=[row['case']['name'],hex(f['0xc10']),f"{f['0xc88']} / {f['0xc8c']:#x}",str(geometry['fields']['0xbc8']),str(info['total_vex_events'])]
        else:
            cells=[row['case']['name'],'복사 미실행','조회 미진입','미실행',str(row['total_vex_events'])+' (실패 반환)']
        header_rows.append('<tr><th scope="row">'+esc(cells[0])+'</th>'+''.join('<td><code>'+esc(c)+'</code></td>' for c in cells[1:])+'</tr>')
    boot_rows=[]
    for row in data['boot_read']['cases']:
        c=row['case']
        cells=[c['name'],hex(c['word']),256 if c['fourth'] else 32,
            row['checkpoints']['nand_ex']['arguments'][3] if 'nand_ex' in row['checkpoints'] else '미진입',
            row['request_vex_events'],'반환 0xf2' if row['result']==0xf2 else 'NAND Ex 본문 직전']
        boot_rows.append('<tr><th scope="row">'+esc(cells[0])+'</th>'+''.join('<td>'+esc(c)+'</td>' for c in cells[1:])+'</tr>')
    ranges=data['source']['selected_e03_ranges']
    values=dict(header_rows=''.join(header_rows),boot_rows=''.join(boot_rows),
        range_count=str(len(ranges)),range_bytes=f"{sum(r['size'] for r in ranges):,}",
        range_rows=''.join(f'<tr><th scope="row"><code>{r["address"]}</code></th><td>{r["size"]:,}</td><td><code>{r["original_file_offset"]}</code></td><td><code class="wrap">{r["sha256"]}</code></td></tr>' for r in ranges),
        firmware_sha=data['input_sha256'],elf_sha=data['analysis_elf_sha256'],report_sha=REPORT_SHA256)
    page=(ROOT/'analysis/nand-boot-read-template.html').read_text(encoding='utf-8')
    for key,value in values.items():page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    output=ROOT/'reports/nand-boot-read.html'
    output.parent.mkdir(exist_ok=True)
    output.write_text(page,encoding='utf-8',newline='\n')
    print('Built reports/nand-boot-read.html')


if __name__=='__main__':main()
