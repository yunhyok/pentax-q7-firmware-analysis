"""Render the three distinct NAND continuation experiments without firmware or angr."""
from build_deep_report import ROOT, read, esc
from check_nand_boot_read import REPORT_SHA256, validate_report


def main():
    data=read('nand-boot-read-checks.json')
    validate_report(data)
    header_cases=data['header_information']['cases']
    boot_cases=data['boot_read']['cases']
    infos=[r for r in header_cases if r.get('information_get')]
    positives=[r for r in boot_cases if r['case']['kind']==1]
    # Fixed facts written in the template prose and diagrams.
    assert len(header_cases)-len(infos)==1
    geometry={r['separate_request9']['fields']['0xbc8'] for r in infos}
    assert geometry=={1041} and -(-0x100000//(16*63))==1041
    assert {r['separate_request9']['vex_events'] for r in infos}=={17}
    assert {r['separate_request9']['return_value'] for r in infos}=={1}
    assert {r['separate_request9']['fields']['0x1cc'] for r in infos}=={0}
    assert all(r['information_get']['fields']['0xc8c']==0x100000 for r in infos)
    assert {r['information_get']['fields']['0xc88'] for r in infos}=={32,256}
    nand_ex=[r['checkpoints']['nand_ex']['arguments'] for r in positives]
    shape={tuple(a[:3]+a[4:]) for a in nand_ex}
    assert shape=={('0x1','0x24002000','0x4','0x1','0x24006000','0x70000eb0','0x10')}
    assert all(int(r['checkpoints']['nand_ex']['arguments'][3],16)==r['case']['word'] for r in positives)
    nulls=[r for r in boot_cases if r['case']['kind'] is None]
    assert len(nulls)==1 and nulls[0]['result']==0xf2 and nulls[0]['driver_status_at_stop']==0xf2
    assert all(r['driver_status_at_stop']==0x90 and r['stop_before']=='0x80053124' for r in positives)
    assert all(r['initial_destination_sha256']==r['final_destination_sha256'] for r in boot_cases)
    assert data['source']['decoded_burn']['size']==216 and data['static_dispatch']['burn_seventh_argument']=='0x80000000'
    failed=[r for r in header_cases if not r.get('information_get')][0]
    assert failed['releases'][0]['return_address']=='0x80056744' and failed['stop_before']=='0x80066b88'
    assert all(r['releases'][0]['return_address']=='0x8008413c' for r in infos)

    header_rows=[]
    for row in header_cases:
        info=row.get('information_get')
        if info:
            f=info['fields']; geo=row['separate_request9']
            cells=[f'<code>{f["0xc10"]:#x}</code>',f"{f['0xc88']} / <code>{f['0xc8c']:#x}</code>",
                   f"<code>+0xbc8</code> = {geo['fields']['0xbc8']}",str(info['total_vex_events'])]
        else:
            cells=['복사 안 함','조회까지 가지 않음','실행 안 함',f"{row['total_vex_events']} (실패 반환)"]
        header_rows.append('<tr><th scope="row"><code>'+esc(row['case']['name'])+'</code></th>'
            +''.join(f'<td>{c}</td>' for c in cells[:3])+f'<td class="n">{cells[3]}</td></tr>')
    boot_rows=[]
    for row in boot_cases:
        c=row['case']
        position=row['checkpoints']['nand_ex']['arguments'][3] if 'nand_ex' in row['checkpoints'] else '들어가지 않음'
        end='반환 <code>0xf2</code>' if row['result']==0xf2 else 'NAND 연산 본문 직전'
        boot_rows.append(f'<tr><th scope="row"><code>{esc(c["name"])}</code></th><td><code>{c["word"]:#x}</code></td>'
            f'<td class="n">{256 if c["fourth"] else 32}</td><td><code>{esc(position)}</code></td>'
            f'<td class="n">{row["request_vex_events"]}</td><td>{end}</td></tr>')
    ranges=data['source']['selected_e03_ranges']
    a=nand_ex[0]
    values=dict(header_rows=''.join(header_rows),boot_rows=''.join(boot_rows),
        header_count=str(len(header_cases)),info_count=str(len(infos)),boot_count=str(len(boot_cases)),
        positive_count=str(len(positives)),geometry_value='1041',geometry_vex='17',
        nand_ex_args=f'[{int(a[0],16)}, {a[1]}, {int(a[2],16)}, word, {int(a[4],16)}, {a[5]}, {a[6]}, {int(a[7],16)}]',
        range_count=str(len(ranges)),range_bytes=f"{sum(r['size'] for r in ranges):,}",
        range_rows=''.join(f'<tr><th scope="row"><code>{r["address"]}</code></th><td class="n">{r["size"]:,}</td><td><code>{r["original_file_offset"]}</code></td><td><code class="wrap">{r["sha256"]}</code></td></tr>' for r in ranges),
        firmware_sha=data['input_sha256'],elf_sha=data['analysis_elf_sha256'],report_sha=REPORT_SHA256)
    page=(ROOT/'analysis/nand-boot-read-template.html').read_text(encoding='utf-8')
    for key,value in values.items():page=page.replace('{{'+key+'}}',value)
    assert '{{' not in page
    output=ROOT/'reports/nand-boot-read.html'
    output.parent.mkdir(exist_ok=True)
    output.write_text(page,encoding='utf-8',newline='\n')
    print('Built reports/nand-boot-read.html')


if __name__=='__main__':main()
