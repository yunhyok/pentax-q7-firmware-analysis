"""Render the bounded NAND ID and boot-header observations in the shared site layout."""
from build_deep_report import ROOT, read, esc
from check_nand_headers import validate_report

VERDICT = {0: '수락', 0x90: '거부', 0xF2: '종류 거부'}


def main():
    data = read('nand-header-checks.json')
    validate_report(data)
    cases = data['parser']['cases']
    entries = data['native_open_entries']
    redirects = data['header_redirect']
    groups = data['parser']['device_table_groups']
    ranges = data['source']['selected_ranges']
    # Fixed facts written in the template prose and diagrams.
    by_name = {r['name']: r for r in cases}
    assert by_name['dc-basic']['fields']['0xc14'] == 5 and by_name['dc-distinct-byte3']['fields']['0xc14'] == 8
    assert by_name['dc-equal-byte3']['fields']['0xc14'] == 5
    assert by_name['dc-kind102']['fields']['0xbf4'] == 0xF9C80 == 1023104
    assert by_name['dc-unsupported-kind']['result'] == 0xF2 and by_name['dc-unsupported-kind']['fields']['0x1cc'] == 0x90
    assert [by_name[n]['result'] for n in ('98-e3-reject', 'ec-6b-reject', 'ec-e3', '98-6b')] == [0x90, 0x90, 0, 0]
    assert [int(r['arguments'][2], 16) for r in entries] == [32, 256]
    assert all(r['initial_c18'] == 0x100 for r in entries)
    assert [r['fields']['0xc18'] for r in entries] == [0x103, 0x105]
    assert [r['read_location_input'] for r in redirects] == [291] * 4
    assert [r['aligned_redirect'] for r in redirects] == [None, 288, 256, 288]
    assert redirects[3]['header_return'] == '0x0' and all(r['header_return'] == '0x24400000' for r in redirects[:3])
    assert sum(len(v) for v in groups.values()) == 191 and len(groups['0x80055784']) == 161
    assert data['source']['f1']['table_entry'] == '0x80063e9c' and data['source']['f1']['target'] == '0x8005590c'
    assert all(not r['native_header_word_200_consumer_executed'] for r in redirects)

    values = {}
    values['parser_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["name"])}</code></th><td><code>{r["supplied_id_hex"]}</code></td>'
        f'<td><code>{r["kind"]:#x}</code></td><td>{VERDICT[r["result"]]}</td><td><code>{r["result"]:#x}</code></td>'
        f'<td class="n"><code>{r["fields"]["0xbf4"]:#x}</code></td><td class="n">{r["fields"]["0xc14"]}</td>'
        f'<td class="n"><code>{r["fields"]["0xc18"]:#x}</code></td></tr>' for r in cases)
    values['entry_rows'] = ''.join(
        f'<tr><th scope="row"><code>{r["supplied_id_hex"]}</code></th><td class="n">{int(r["arguments"][2],16)}</td>'
        f'<td><code>{r["initial_c18"]:#x} → {r["fields"]["0xc18"]:#x}</code></td>'
        f'<td class="n">{r["vex_events"]}</td></tr>' for r in entries)
    values['redirect_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["case"]["scenario"])}</code></th><td class="n">{r["derived_stride"]}</td>'
        f'<td><code>{r["branch"][0]["word"]}</code></td><td>'
        + ' → '.join(f'{e["operation"]}@{e["position"]} ×{e["count"]} (상태 {e["status"]})' for e in r['io'])
        + f'</td><td><code>{r["header_return"]}</code></td><td class="n">{len(r["modeled_releases"])}</td>'
        f'<td class="n">{r["total_vex_events"]}</td></tr>' for r in redirects)
    values['device_rows'] = ''.join(
        f'<tr><th scope="row"><code>{target}</code></th><td class="n">{len(ids)}</td><td>'
        + (' '.join(f'<code>{i}</code>' for i in ids) if len(ids) <= 8 else
           f'{" ".join(f"<code>{i}</code>" for i in ids[:3])} 외 {len(ids) - 3}개(거부 경로)')
        + '</td></tr>' for target, ids in groups.items())
    values['model_rows'] = ''.join(
        f'<tr><th scope="row">{label}</th><td><code>{address}</code></td><td>{esc(text)}</td></tr>'
        for key, label in (('native_open', '매체 열기'), ('id_response', '식별 응답'), ('header_body', '헤더 함수'))
        for address, text in data['modeled_apis'][key].items())
    values['range_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["name"])}</code></th><td><code>{r["address"]}</code></td>'
        f'<td class="n">{r["size"]:,}</td><td><code>{r["original_file_offset"]}</code></td>'
        f'<td><code class="wrap">{r["sha256"]}</code></td></tr>' for r in ranges)
    values['parser_count'] = str(len(cases))
    values['entry_count'] = str(len(entries))
    values['redirect_count'] = str(len(redirects))
    values['case_total'] = str(len(cases) + len(entries) + len(redirects))
    values['entry_vex'] = ' / '.join(str(r['vex_events']) for r in entries)
    values['redirect_vex'] = ' / '.join(str(r['total_vex_events']) for r in redirects)
    values['range_count'] = str(len(ranges))
    values['word_count'] = str(len(data['source']['words']))
    values['table_entries'] = str(sum(len(v) for v in groups.values()))
    values['reject_entries'] = str(len(groups['0x80055784']))
    values['firmware_sha'] = data['input_sha256']
    values['elf_sha'] = data['analysis_elf_sha256']
    html = (ROOT/'analysis/nand-header-template.html').read_text(encoding='utf-8')
    for key, value in values.items():
        html = html.replace('{{'+key+'}}', value)
    assert '{{' not in html
    (ROOT/'nand-header-report.html').write_text(html,encoding='utf-8',newline='\n')
    print('Built nand-header-report.html')


if __name__ == '__main__':
    main()
