"""Build reports/lens-firmware-update.html from analysis/lens-firmware-update.json."""
from __future__ import annotations

from html import escape
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from check_lens_firmware_update import validate_report


def load_record() -> dict:
    return json.loads((ROOT / 'analysis/lens-firmware-update.json').read_text(encoding='utf-8'))


def _diagram() -> str:
    svg = [
        '<svg class="dg" viewBox="0 0 800 228" role="img" aria-labelledby="dg-lens-title dg-lens-desc">',
        '<title id="dg-lens-title">Q 마운트 렌즈 업데이트 파일의 구획과 두 가지 CRC 범위</title>',
        '<desc id="dg-lens-desc">전체 262,288바이트 파일은 앞 128바이트 헤더, 가운데 262,144바이트 렌즈 ROM 본문, 끝 16바이트 꼬리로 나뉩니다. 헤더 오프셋 0x30에는 본문 전체의 CRC가 들어가고, 파일 끝 2바이트에는 앞 262,286바이트 전체의 CRC가 들어갑니다.</desc>',
        '<rect class="b" x="12" y="24" width="176" height="84" rx="8"/>',
        '<text class="t" x="24" y="50">헤더 (128B)</text>',
        '<text class="s mono" x="24" y="72">0x0000..0x007f</text>',
        '<text class="s" x="24" y="93">ID·버전·0x30 LOM CRC</text>',
        '<rect class="b ok" x="200" y="24" width="430" height="84" rx="8"/>',
        '<text class="t" x="214" y="50">렌즈 ROM 본문 LOM (256KiB = 262,144B)</text>',
        '<text class="s mono" x="214" y="72">0x0080..0x4007f</text>',
        '<text class="s" x="214" y="93">PENTAX 식별 문자열 · 버전 문자열 · 실행 코드</text>',
        '<rect class="b key" x="642" y="24" width="146" height="84" rx="8"/>',
        '<text class="t" x="654" y="50">꼬리 (16B)</text>',
        '<text class="s mono" x="654" y="72">0x40080..0x4008f</text>',
        '<text class="s" x="654" y="93">끝 2B = 파일 CRC</text>',
        '<path class="e ok" d="M200 132H630"/>',
        '<text class="n" x="204" y="152">LOM CRC-16/CCITT 범위 (256KiB) → 헤더 0x30과 일치 (0x2668 / 0xfea2)</text>',
        '<path class="e" d="M12 180H774"/>',
        '<text class="n" x="16" y="200">전체 파일 CRC-16/CCITT 범위 (262,286B) → 끝 2바이트와 일치 (0x1ca0 / 0x1f20)</text>',
        '</svg>',
    ]
    return ''.join(svg)


def render(record: dict) -> str:
    validate_report(record)
    imgs = record['lens_images']
    if len(imgs) < 2:
        raise ValueError('expected fwlq101.bin and fwlq102.bin records')
    a, b = imgs[0], imgs[1]

    rows = [
        ('파일 크기', f'{a["size_bytes"]:,} B (<code>0x{a["size_bytes"]:x}</code>)', f'{b["size_bytes"]:,} B (<code>0x{b["size_bytes"]:x}</code>)'),
        ('SHA-256', f'<code class="wrap">{a["sha256"]}</code>', f'<code class="wrap">{b["sha256"]}</code>'),
        ('체크 바이트 (<code>0x00</code>)', str(a['check_byte']), str(b['check_byte'])),
        ('렌즈 ID (<code>0x02..0x03</code>)', str(a['lens_id']), str(b['lens_id'])),
        ('렌즈 이름 (<code>0x04..0x1f</code>)', f'<code>{escape(a["lens_name"])}</code>', f'<code>{escape(b["lens_name"])}</code>'),
        ('헤더 버전 (<code>0x22..0x25</code>)', '.'.join(map(str, a['fw_version'])), '.'.join(map(str, b['fw_version']))),
        ('본문 내 버전 / 날짜', f'<code>{escape(a["lens_version_string"])}</code> ({escape(a["build_date"])})',
         f'<code>{escape(b["lens_version_string"])}</code> ({escape(b["build_date"])})'),
        ('LOM 크기 / 시작 위치', f'<code>0x{a["lom_size"]:x}</code> / <code>0x{a["lom_offset"]:x}</code>',
         f'<code>0x{b["lom_size"]:x}</code> / <code>0x{b["lom_offset"]:x}</code>'),
        ('LOM CRC (헤더 <code>0x30</code> · 에뮬레이션)',
         f'<code>0x{a["lom_crc_header"]:04x}</code> (<code>0x{a["emu_lom_crc"]:04x}</code>)',
         f'<code>0x{b["lom_crc_header"]:04x}</code> (<code>0x{b["emu_lom_crc"]:04x}</code>)'),
        ('파일 CRC (끝 2B · 에뮬레이션)',
         f'<code>0x{a["file_crc_trailer"]:04x}</code> (<code>0x{a["emu_file_crc"]:04x}</code>)',
         f'<code>0x{b["file_crc_trailer"]:04x}</code> (<code>0x{b["emu_file_crc"]:04x}</code>)'),
    ]
    lens_rows = ''.join(f'<tr><th scope="row">{k}</th><td>{va}</td><td>{vb}</td></tr>' for k, va, vb in rows)

    case_rows = []
    for c in record['execution_check_cases']:
        tail_logs = [line for line in c['logs'] if any(tag in line for tag in (
            'AGREEMENT', 'DISAGREEMENT', 'FAILED', 'CHECK_BYTE', 'CALC_FILE_CRC'
        ))]
        if not tail_logs:
            tail_logs = c['logs'][-2:]
        case_rows.append(
            f'<tr><th scope="row"><code>{escape(c["case"])}</code></th>'
            f'<td class="n">{c["mounted_lens_id"]}</td>'
            f'<td><code>{escape(c["card_filename"])}</code></td>'
            f'<td class="n"><strong>{c["return_value"]}</strong></td>'
            f'<td><code>{escape(" / ".join(tail_logs))}</code></td></tr>'
        )

    routines = record['routines']
    values = {
        '{{GET_CRC_ADDR}}': routines['GetCrc_BYTE'],
        '{{EXEC_CHECK_ADDR}}': routines['UserLensFirmwareUpdateExecutionCheck'],
        '{{EXEC_ADDR}}': routines['UserLensFirmwareUpdateExecution'],
        '{{FILENAME_ADDR}}': routines['GetLensFirmupFileNamePLC'],
        '{{LENS_ID_ADDR}}': routines['GetLensIdPLC'],
        '{{DIAGRAM}}': _diagram(),
        '{{LENS_ROWS}}': lens_rows,
        '{{CASE_ROWS}}': ''.join(case_rows),
    }
    text = (ROOT / 'analysis/lens-firmware-update-template.html').read_text(encoding='utf-8')
    for key, val in values.items():
        if key not in text:
            raise ValueError(f'Missing template marker: {key}')
        text = text.replace(key, val)
    if '{{' in text:
        raise ValueError('Unexpanded template marker remaining')
    return text


def main() -> int:
    html = render(load_record())
    (ROOT / 'reports').mkdir(exist_ok=True)
    (ROOT / 'reports/lens-firmware-update.html').write_text(html, encoding='utf-8', newline='\n')
    print('Built reports/lens-firmware-update.html')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
