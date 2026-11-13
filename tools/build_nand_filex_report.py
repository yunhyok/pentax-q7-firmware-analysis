"""Build the NAND FileX report from its pinned JSON, without firmware or angr."""
from hashlib import sha256
from html import escape
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORT_SHA256 = 'fddd47dea0a5cd639aa2bda20c137c47114c8851e8c8a5ff23a3440655375070'


def canonical(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def rows(items):
    return ''.join(
        '<tr>' + ''.join('<td>' + escape(str(value)) + '</td>' for value in item) + '</tr>'
        for item in items
    )


def main():
    data = json.loads((ROOT / 'analysis/nand-filex-checks.json').read_bytes())
    if canonical(data) != REPORT_SHA256:
        raise ValueError('complete FileX report differs')
    native = data['native_trace']
    static = data['static_evidence']
    standalone = json.loads((ROOT / 'analysis/nand-filex-source.json').read_bytes())
    if static != standalone:
        raise ValueError('standalone static FileX evidence differs')

    counts = {segment: sum(row['segment'] == segment for row in static['ranges']) for segment in ('E03', 'E05')}
    values = {
        'checkpoint_rows': rows((row['name'], row['pc'], row['vex_events']) for row in native['checkpoints']),
        'e03_ranges': str(counts['E03']),
        'e05_ranges': str(counts['E05']),
        'firmware_sha': data['input_sha256'],
        'elf_sha': data['analysis_elf_sha256'],
        'native_sha': canonical(native),
        'static_sha': canonical(static),
    }
    page = (ROOT / 'analysis/nand-filex-template.html').read_text(encoding='utf-8')
    for key, value in values.items():
        page = page.replace('{{' + key + '}}', value)
    if '{{' in page:
        raise ValueError('unresolved HTML placeholder')
    output = ROOT / 'reports/nand-filex.html'
    output.parent.mkdir(exist_ok=True)
    output.write_text(page, encoding='utf-8', newline='\n')
    print('Built reports/nand-filex.html')


if __name__ == '__main__':
    main()
