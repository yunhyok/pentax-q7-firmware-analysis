"""The published colour engine tables are internally consistent (no firmware needed)."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
TABLES = json.loads((ROOT/'analysis/color-engine-tables.json').read_text(encoding='utf-8'))
IDENTITY = [8192, 0, 0, 0, 8192, 0, 0, 0, 8192]


class ColorTableTests(unittest.TestCase):
    def test_input_and_groups(self):
        evidence = json.loads((ROOT/'analysis/segment-decode.json').read_text(encoding='utf-8'))
        self.assertEqual(TABLES['firmware']['sha256'], evidence['input_sha256'])
        counts = {group: len(TABLES[group]) for group in
                  ('matrices_s16', 'matrix_sets_6_s16', 'tone_u16', 'dng_color_matrix_s32_pairs', 'ycbcr_s16')}
        self.assertEqual(counts, {'matrices_s16': 43, 'matrix_sets_6_s16': 11, 'tone_u16': 22,
                                  'dng_color_matrix_s32_pairs': 2, 'ycbcr_s16': 1})

    def test_addresses_lie_in_the_decoded_segment(self):
        segment = next(item for item in json.loads(
            (ROOT/'analysis/segment-decode.json').read_text(encoding='utf-8'))['segments'] if item['name'] == 'E04')
        start, end = segment['virtual_address'], segment['virtual_address'] + segment['decoded_size']
        for group, table in TABLES.items():
            if not isinstance(table, dict) or group == 'firmware':
                continue
            for name, record in table.items():
                with self.subTest(name=name):
                    self.assertTrue(start <= int(record['address'], 16) < end)

    def test_q13_matrices_preserve_white(self):
        matrices = TABLES['matrices_s16']
        for name, record in matrices.items():
            values = record['values']
            if name.startswith(('cnsMakeUpMatrix', 'cnarsSatCtlMatrix', 'cnsCameraBasicMatrix')) and 'Inverse' not in name:
                with self.subTest(name=name):
                    # Equal RGB stays equal: every row sums to 1.0 within one unit of rounding.
                    for row in range(3):
                        self.assertLessEqual(abs(sum(values[3 * row:3 * row + 3]) - 8192), 1)
        for name in ('cnsFlatMatrix', 'cnsMakeUpMatrixNatural', 'cnarsSatCtlMatrix04'):
            self.assertEqual(matrices[name]['values'], IDENTITY)
        for mode, record in TABLES['matrix_sets_6_s16'].items():
            self.assertEqual(len(record['values']), 54, mode)

    def test_hue_and_ycbcr_use_q8(self):
        matrices = TABLES['matrices_s16']
        identity = [256, 0, 0, 0, 256, 0, 0, 0, 256]
        self.assertEqual(matrices['cnsHueShiftMatrix04']['values'], identity)
        self.assertEqual(matrices['cnsHueShiftDisableMatrix']['values'], identity)
        for index in range(9):
            values = matrices[f'cnsHueShiftMatrix{index:02d}']['values']
            self.assertEqual(values[:3] + [values[3], values[6]], [256, 0, 0, 0, 0])   # luma is untouched
            self.assertEqual(values[5], -values[7])                                    # a rotation of Cb, Cr
        self.assertEqual(TABLES['ycbcr_s16']['arcnwYCbCrConversionMatrixDefault']['values'],
                         [77, 150, 29, -43, -85, 128, 128, -107, -21])

    def test_tone_curves_rise_from_zero(self):
        for name, record in TABLES['tone_u16'].items():
            values = record['values']
            with self.subTest(name=name):
                self.assertEqual(len(values), 256)
                self.assertEqual(values[0], 0)
                self.assertTrue(all(a <= b for a, b in zip(values, values[1:])))
        families = {name[len('cnarwBasicTone'):] for name in TABLES['tone_u16'] if 'Basic' in name}
        self.assertEqual(families, {f'{column}{family}' for column in (128, 256, 512, 1024, 2048)
                                    for family in ('Low', 'Middle', 'High')})

    def test_dng_matrices_share_one_denominator(self):
        for name, record in TABLES['dng_color_matrix_s32_pairs'].items():
            with self.subTest(name=name):
                self.assertEqual(record['values'][1::2], [65536] * 9)


if __name__ == '__main__':
    unittest.main()
