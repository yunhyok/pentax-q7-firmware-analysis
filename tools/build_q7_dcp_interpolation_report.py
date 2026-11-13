"""Build the Q7 interpolation page after validating the complete research witness."""
from html import escape
from pathlib import Path

from check_q7_dcp_interpolation import load_record, validate_report, canonical

ROOT = Path(__file__).resolve().parents[1]


def render(record):
    observations = validate_report(record)
    rows = []
    for row in observations['probes']:
        cells = [row['table'].replace('Profile', '')]
        for key in ('input_hsv_degrees', 'weighted_coefficients_degrees_scale_scale', 'derived_output_hsv_degrees'):
            cells.append(', '.join(f'{v:.9g}' for v in row[key]))
        rows.append('<tr>' + ''.join('<td>' + escape(cell) + '</td>' for cell in cells) + '</tr>')
    text = (ROOT / 'analysis/q7-dcp-interpolation-template.html').read_text(encoding='utf-8')
    for key, value in {'{{PROBES}}': ''.join(rows), '{{OBSERVATIONS_SHA}}': canonical(observations)}.items():
        if text.count(key) != 1:
            raise ValueError('Expected one template marker: ' + key)
        text = text.replace(key, value)
    if '{{' in text:
        raise ValueError('Unexpanded template marker')
    return text


def main():
    text = render(load_record())
    (ROOT / 'reports').mkdir(exist_ok=True)
    (ROOT / 'reports/q7-dcp-interpolation.html').write_text(text, encoding='utf-8', newline='\n')
    print('Built q7-dcp-interpolation.html')


if __name__ == '__main__':
    main()
