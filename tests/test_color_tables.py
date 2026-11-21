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
        counts = {group: len(table) for group, table in TABLES.items() if group not in ('firmware', 'scope')}
        self.assertEqual(counts, {'matrices_s16': 44, 'matrix_sets_6_s16': 11, 'tone_u16': 22,
                                  'dng_color_matrix_s32_pairs': 2, 'ycbcr_s16': 1, 'chroma_offsets_s16': 9,
                                  'tone_constants_u16': 3, 'composition_rate_u16': 1, 'custom_image_records_u8': 23,
                                  'chroma_suppression_u16': 1, 'anonymous': 4})

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
        for name, record in TABLES['matrix_sets_6_s16'].items():
            # In v1.01 the six hue-sector matrices of a mode all equal its single matrix.
            self.assertEqual(record['values'], matrices[name[:-1]]['values'] * 6, name)

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

    def test_tone_constants_and_anonymous_tables(self):
        constants = {name: record['values'][0] for name, record in TABLES['tone_constants_u16'].items()}
        self.assertEqual(constants, {'cnwBasicToneSaturationPointMin': 16130, 'cnwBasicToneSaturationPointOutput': 4095,
                                     'cnwBasicToneBaseNumber': 64})
        anonymous = {name: record['values'] for name, record in TABLES['anonymous'].items()}
        self.assertEqual(anonymous['key_table_u32'], [512, 431, 362, 304, 256, 215, 181, 152, 128])
        self.assertEqual(anonymous['reversal_bounds_u32'], [128, 181, 256, 362, 512, 724, 1024])
        self.assertEqual(anonymous['cm_base_matrix_s16'], [256, 0, 0, 0, 256, 0, 0, 0, 256])
        self.assertEqual(anonymous['lut_node_levels_u16'], [0, 512, 1024, 1536, 2048, 2560, 3072, 3584, 4095])
        # Every regular curve passes through 64 x 118 where its column number says (index = number / 16).
        for name, record in TABLES['tone_u16'].items():
            number = int(''.join(ch for ch in name[len('cnarw'):] if ch.isdigit()))
            if name.startswith('cnarwBasicTone'):
                self.assertEqual(record['values'][number // 16], 64 * 118, name)

    def test_composition_rates_rise_from_zero_to_one(self):
        # The basic gamma joins two tone curves with these rates; 2048 = the outer curve alone.
        rates = TABLES['composition_rate_u16']['cnwHighlightShadowCompositionRate2048']['values']
        self.assertEqual((len(rates), rates[0], rates[32], rates[-1]), (97, 0, 1536, 2048))
        self.assertTrue(all(a <= b for a, b in zip(rates, rates[1:])))

    def test_custom_image_records_and_toning(self):
        records = {name[len('cntCustomImageUnit'):]: record['values'] for name, record in TABLES['custom_image_records_u8'].items()}
        # mode id, saturation, contrast, sharpness, key (settings stored 0..8, 4 = 0) ... toning colour at byte 8
        self.assertEqual(records['Natural'][:9], [0, 4, 4, 4, 4, 4, 0, 4, 0])
        self.assertEqual(records['Vivid'][:5], [1, 4, 5, 5, 4])
        self.assertEqual(records['PopTune'][:5], [8, 4, 7, 5, 6])
        self.assertEqual(records['Honoka'][:5], [5, 4, 1, 2, 8])
        self.assertEqual(records['BleachBypass'][:5] + [records['BleachBypass'][8]], [7, 4, 8, 3, 0, 1])
        self.assertEqual([records[name][0] for name in ('Portrait', 'Landscape', 'Miyabi', 'Reversal', 'CrossProcess', 'Monotone')],
                         [2, 3, 4, 6, 9, 10])
        chroma = {name: record['values'] for name, record in TABLES['chroma_offsets_s16'].items()}
        self.assertEqual(chroma['cnarsCbAddition'], [0, -32, -64, -64, -32, 32, 64, 64, 32])
        self.assertEqual(chroma['cnarsCrAddition'], [0, -64, 0, 48, 64, 64, 48, 0, -64])
        self.assertEqual((chroma['cnarsCbOffset'][4], chroma['cnarsCrOffset'][4]), (0, 0))      # monochrome toning 0
        self.assertEqual(chroma['cnarsCbCrOAdditionNon'], [0] * 9)
        ratio = TABLES['chroma_suppression_u16']['arwCChromaSuppressionRatioLut']['values']
        self.assertEqual((len(ratio), ratio[0], ratio[256], ratio[512]), (2048, 8192, 8192, 7168))
        self.assertEqual((ratio[2047], set(ratio[:257])), (4096, {8192}))
        self.assertTrue(all(b <= a + 1 for a, b in zip(ratio, ratio[1:])))      # falls, with one-step rounding ripples

    def test_dng_d65_matrix_matches_the_published_q_s1_matrix(self):
        # LibRaw colordata.cpp, Pentax Q-S1 (the Q7's sensor); values x 1e-4.
        published = [12995, -5593, -1107, -1879, 10139, 2027, -64, 1233, 4919]
        values = TABLES['dng_color_matrix_s32_pairs']['arcnlDNGColorMatrix2']['values']
        self.assertEqual([round(values[2 * i] / values[2 * i + 1] * 10000) for i in range(9)], published)

    def test_dng_matrices_share_one_denominator(self):
        for name, record in TABLES['dng_color_matrix_s32_pairs'].items():
            with self.subTest(name=name):
                self.assertEqual(record['values'][1::2], [65536] * 9)


if __name__ == '__main__':
    unittest.main()
