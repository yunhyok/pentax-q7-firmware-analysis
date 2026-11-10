"""Build the HDR buffer identity and color-pass report."""
from build_deep_report import ROOT, read, esc
from verify_routing import witnesses


def main():
    buffer, passes = read('buffer-followup.json'), read('pass-followup.json')
    handoff, comparison = read('color-handoff-checks.json'), read('followup-comparison.json')
    values = {}
    names = {'cm': 'CM', 'fc1': 'FC1'}
    def coeffs(values_):
        return '<span class="small">' + ', '.join(str(v).replace('-', '−') for v in values_) + '</span>'
    cases = handoff['cases']
    values['handoff_rows'] = ''.join(
        f'<tr><th scope="row">{names[c["case"]]}</th><td><code>{c["setter"]}</code> → <code>{c["writer"]}</code></td>'
        f'<td>{coeffs(c["initial_coefficients"])}</td><td>{coeffs(c["resulting_coefficients"])}</td>'
        f'<td>{"예" if c["coefficients_preserved"] else "아니오(교체)"}</td><td class="n">{len(c["mmio_writes"])}</td></tr>'
        for c in cases)
    values['handoff_hashes'] = ''.join(
        f'<tr><th scope="row">{names[c["case"]]}</th><td><code class="wrap">{c["object_sha256"]}</code></td></tr>' for c in cases)
    values['handoff_mmio'] = str(sum(len(c['mmio_writes']) for c in cases))
    matrix = buffer['hdr_matrix']['signed_halfwords']
    assert matrix == passes['hdr_integration']['upper_descriptor']['signed_halfwords']
    labels = ('1행', '2행', '3행')
    def cell(v):
        return f'<td class="n">{v:,} <span class="muted">({v/2048:.3f})</span></td>'.replace('-', '−')
    values['hdr_matrix_rows'] = ''.join(
        f'<tr><th scope="row">{labels[r]}</th>' + ''.join(cell(v) for v in matrix[3*r:3*r+3]) + cell(sum(matrix[3*r:3*r+3])) + '</tr>'
        for r in range(3))
    values['hdr_trailing'] = ', '.join(f'{v:,}' for v in buffer['hdr_matrix']['trailing_halfwords'])
    tables = passes['pass_selection']['filter_tables']
    assert tables['common']['nonzero_ids'] == [] and tables['final_only']['nonzero_ids'] == [0]
    values['common_ids'] = str(tables['common']['inspected_ids'])
    values['final_ids'] = str(tables['final_only']['inspected_ids'])
    docs = (buffer, passes)
    values['fn_buffer'] = str(len(buffer['selected_functions']))
    values['fn_pass'] = str(len(passes['selected_functions']))
    values['function_count'] = str(len({f['address'] for d in docs for f in d['selected_functions']}))
    values['word_count'] = str(sum(len(list(witnesses(d))) for d in docs))
    values['k3_commit'] = esc(comparison['commit'])
    values['k3_base'] = comparison['repository'] + '/blob/' + comparison['commit'] + '/analysis/'
    page = (ROOT/'analysis/pixel-template.html').read_text(encoding='utf-8')
    for key, value in values.items():
        page = page.replace('{{'+key+'}}', value)
    assert '{{' not in page
    (ROOT/'pixel-report.html').write_text(page, encoding='utf-8', newline='\n')
    print('Built pixel-report.html')


if __name__ == '__main__':
    main()
