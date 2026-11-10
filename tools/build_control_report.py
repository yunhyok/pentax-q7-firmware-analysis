"""Build the HDR per-pass FC1 enable and submitted-pass report (hdr-control-report.html)."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses


def main():
    v = {}
    control = read('control-followup.json')
    passes_doc = read('hdr-pass-followup.json')
    enable = read('fc1-enable-checks.json')
    fresh = passes_doc['fresh_hdr']
    passes = control['fresh_hdr']['passes']

    # Per-pass table.
    rows = []
    for p in passes:
        payload = p['expected_payload']
        regs = p['expected_direct_register_values']
        on = '켜짐' if payload['bypass_word'] == 0 else '꺼짐'
        rows.append(
            f"<tr><th scope=\"row\">{p['pass_index']}{' · 마지막' if p['final_pass'] else ''}</th>"
            f"<td class=\"n\">{p['topology_location']}</td><td>{esc(p['pass_class'])}</td>"
            f"<td class=\"n\">{p['topology_word']}</td><td class=\"n\">{payload['bypass_word']}</td>"
            f"<td class=\"n\">{payload['mode_1_flag_word']}</td><td class=\"n\">{regs['0xb60000ec']}</td>"
            f"<td class=\"n\">{regs['0xb60000fc']}</td><td>{on}</td></tr>")
    v['pass_rows'] = ''.join(rows)

    # Diagram: one column per pass, generated from the evidence.
    cols = []
    for i, p in enumerate(passes):
        x = 8 + i * 198
        on = p['expected_payload']['bypass_word'] == 0
        cols.append(
            f'<rect class="b {"key" if on else "mute"}" x="{x}" y="140" width="182" height="96" rx="8"/>'
            f'<text class="t" x="{x + 12}" y="166">패스 {p["pass_index"]} · {esc(p["pass_class"])}</text>'
            f'<text class="s" x="{x + 12}" y="190">location {p["topology_location"]} · T = {p["topology_word"]}</text>'
            f'<text class="s" x="{x + 12}" y="214">FC1 {"켜짐" if on else "꺼짐"} · 제어 워드 {p["expected_payload"]["mode_1_flag_word"]}</text>'
            f'<path class="e" d="M{x + 91} 118V138" marker-end="url(#dg-topo-ah)"/>')
    last = 8 + fresh['final_index'] * 198
    cols.append(f'<text class="n tk" x="{last + 4}" y="258">↑ 마지막 패스 (i = N−1)</text>')
    v['pass_columns'] = ''.join(cols)
    v['pass_count'] = str(fresh['count'])
    v['final_index'] = str(fresh['final_index'])
    v['range'] = f"[{fresh['start']}, {fresh['end_exclusive']})"
    v['locations'] = ' → '.join(str(x) for x in fresh['topology_locations'])
    v['classes'] = ' → '.join(fresh['pass_classes'])
    v['t_values'] = '·'.join(str(x) for x in fresh['T'])
    v['enable_values'] = '·'.join(
        '켜짐' if p['expected_payload']['bypass_word'] == 0 else '꺼짐' for p in passes)

    # FC1 enable replay cases.
    v['enable_rows'] = ''.join(
        f'<tr><th scope="row"><code>{c["payload_word"]:#010x}</code></th><td class="n">{c["payload_word"] & 0xff}</td>'
        f'<td class="n">{c["enabled"]}</td><td class="n">{c["mmio"][2]}</td><td class="n">{c["cbc"][1]}</td></tr>'
        for c in enable['replay']['cases'])
    v['enable_case_count'] = str(len(enable['replay']['cases']))
    v['control_case_count'] = str(len(control['replay']['cases']))
    v['hdr_stub_count'] = str(len(passes_doc['replay']['stubs']))
    v['hdr_stubs'] = ''.join(
        f'<tr><th scope="row"><code>{pc}</code></th><td>{esc(name)}</td></tr>'
        for pc, name in passes_doc['replay']['stubs'].items())

    docs = [control, passes_doc, enable]
    v['function_count'] = str(len({f['address'] for d in docs for f in d['selected_functions']}))
    v['word_count'] = f"{sum(len(list(witnesses(d))) for d in docs):,}"
    k3 = read('control-comparison.json')
    v['k3_commit'] = k3['latest_public_main_sha_verified_via_gh']
    v['k3_base'] = k3['k3_repository'] + '/blob/' + v['k3_commit'] + '/analysis/'

    page = (ROOT / 'analysis/control-template.html').read_text(encoding='utf-8')
    for key, value in v.items():
        page = page.replace('{{' + key + '}}', value)
    assert '{{' not in page
    (ROOT / 'hdr-control-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built hdr-control-report.html')


if __name__ == '__main__':
    main()
