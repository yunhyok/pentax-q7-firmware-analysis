"""Render the Q7 lens/ISP/output report; also defines the shared graph() helper."""
from build_deep_report import ROOT, read, esc, diagram


def graph(key, title, nodes, edges, height, caption, source):
    return diagram(key, title, nodes, edges, height, caption).replace(
        'analysis/deep-evidence.json">[S3]', f'analysis/{source}">[근거]')


def main():
    from verify_routing import witnesses
    lens, isp, out = read('lens-routing.json'), read('isp-routing.json'), read('output-routing.json')
    checks, comparison = read('isp-register-checks.json'), read('routing-comparison.json')
    values = {}
    requests = {0: '검색 시작 (SetFocusSerchStart)', 1: '정지 (SetFocusMovementStop)',
                2: '위치 이동 (SetFocusLocationDrive)', 3: '검색 보류 → VD 동기화 처리'}
    payloads = {c['mode']: c['local_payload_hex'] for c in lens['bounded_replay']['cases']}
    modes = sorted(lens['queue']['modes'], key=lambda m: m['mode'])
    values['lens_rows'] = ''.join(
        f'<tr><th scope="row">{m["mode"]}</th><td>{esc(requests[m["mode"]])}</td>'
        f'<td class="n">{m["queue_message"]}{" (VD)" if m["mode"] == 3 else ""}</td>'
        f'<td>({", ".join(map(str, m["arguments_a0_a3"]))}, …)</td><td><code>{payloads[m["mode"]]}</code></td></tr>'
        for m in modes)
    values['lens_sites'] = ''.join(
        f'<tr><th scope="row">{m["mode"]}</th><td><code>{m["mode_entry"]}</code></td><td><code>{m["queue_send_call"]}</code></td>'
        f'<td><code>{m["queue_table_slot"]}</code></td><td><code>{m["worker_target"]}</code></td><td><code>{m["lens_communication_call"]}</code></td></tr>'
        for m in modes)
    values['matrix_rows'] = ''.join(
        f'<tr><th scope="row">{i}</th><td><code>+0x{0x14+2*i:02x}</code></td><td><code>0x{0xb6000200+4*i:08x}</code></td>'
        f'<td><code>0x{0xb60000c0+4*i:08x}</code></td></tr>' for i in range(9))
    def span(addresses):
        return ' '.join(f'<code>{a}</code>' for a in addresses)
    values['register_rows'] = ''.join(
        f'<tr><th scope="row">{esc(r["name"])}</th><td><code>{r["writer"]}</code></td><td>{span(r["addresses"])}</td>'
        f'<td>{esc(r["source"])}</td><td>{esc(r["condition"])}</td></tr>' for r in isp['registers'])
    targets = {0x803537a4: 'CM 기록', 0x8031f750: 'FC1 기록', 0x80354970: 'FC2 기록',
               0x801d585c: '통계 GC 표', 0x801d58c4: '통계 DCI 표'}
    def condition(case):
        data = case['input']
        return f'갱신 표시 {data["dirty"]}' if 'dirty' in data else f'데이터 {data["words"]}개'
    cases = checks['cases']
    values['isp_case_rows'] = ''.join(
        f'<tr><th scope="row">{targets[c["address"]]} <code>0x{c["address"]:08x}</code></th><td>{condition(c)}</td>'
        f'<td class="n">{c["mmio_writes"]}</td><td class="n">{c["clock_stub_calls"]}</td><td class="n">{c["assertions"]}</td>'
        f'<td>{"통과" if c["passed"] else "실패"}</td></tr>' for c in cases)
    values['isp_mmio'] = str(sum(c['mmio_writes'] for c in cases))
    values['isp_clock'] = str(sum(c['clock_stub_calls'] for c in cases))
    values['isp_checks'] = str(sum(c['assertions'] for c in cases))
    assert all(c['passed'] for c in cases) and len(cases) == 10
    counts = [len(list(witnesses(d))) for d in (lens, isp, out)]
    values['word_lens'], values['word_isp'], values['word_out'] = map(str, counts)
    values['word_total'] = str(sum(counts))
    values['fn_lens'] = str(len(lens['selected_functions']))
    values['fn_out'] = str(len(out['selected_functions']))
    values['isp_count'] = str(isp['decompilation']['count'])
    values['function_rows'] = ''.join(
        f'<tr><td>{esc(f["name"])}</td><td><code>0x{f["address"]:08x}</code></td><td class="n">{f["size"]:,}</td></tr>'
        for f in sorted(isp['selected_functions'], key=lambda f: f['address']))
    values['k3_commit'] = comparison['commit']
    page = (ROOT/'analysis/routing-template.html').read_text(encoding='utf-8')
    for key,value in values.items(): page = page.replace('{{'+key+'}}',value)
    assert '{{' not in page, 'unresolved routing template field'
    (ROOT/'routing-report.html').write_text(page,encoding='utf-8',newline='\n')
    print('Built routing-report.html')


if __name__ == '__main__':
    main()
