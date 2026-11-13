"""Render the bounded NAND ID and boot-header observations in the shared site layout."""
from build_deep_report import ROOT, read, esc
from check_nand_headers import validate_report


def main():
    data = read('nand-header-checks.json')
    validate_report(data)
    values = {}
    values['parser_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["name"])}</code></th><td><code>{r["supplied_id_hex"]}</code></td>'
        f'<td><code>{r["kind"]:#x}</code></td><td><code>{r["result"]:#x}</code></td>'
        f'<td><code>{r["fields"]["0xbf4"]:#x}</code></td><td>{r["fields"]["0xc14"]}</td>'
        f'<td><code>{r["fields"]["0xc18"]:#x}</code></td></tr>' for r in data['parser']['cases'])
    values['entry_rows'] = ''.join(
        f'<tr><th scope="row"><code>{r["supplied_id_hex"]}</code></th><td>{int(r["arguments"][2],16)}</td>'
        f'<td><code>{r["initial_c18"]:#x} → {r["fields"]["0xc18"]:#x}</code></td>'
        f'<td class="n">{r["vex_events"]}</td></tr>' for r in data['native_open_entries'])
    values['redirect_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["case"]["scenario"])}</code></th><td>{r["derived_stride"]}</td>'
        f'<td><code>{r["branch"][0]["word"]}</code></td><td>'
        + ' → '.join(f'{e["operation"]}@{e["position"]} ×{e["count"]} (상태 {e["status"]})' for e in r['io'])
        + f'</td><td><code>{r["header_return"]}</code></td><td>{len(r["modeled_releases"])}</td>'
        f'<td>{r["total_vex_events"]}</td></tr>' for r in data['header_redirect'])
    values['range_rows'] = ''.join(
        f'<tr><th scope="row"><code>{esc(r["name"])}</code></th><td><code>{r["address"]}</code></td>'
        f'<td>{r["size"]:,}</td><td><code>{r["original_file_offset"]}</code></td>'
        f'<td><code class="wrap">{r["sha256"]}</code></td></tr>' for r in data['source']['selected_ranges'])
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
