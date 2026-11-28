"""Validate published Q7 lens firmware update verification JSON and HTML builder."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import build_lens_firmware_update_report as builder
import check_lens_firmware_update as checker


class LensFirmwareUpdateTests(unittest.TestCase):
    def test_published_record_valid(self):
        record = builder.load_record()
        checker.validate_report(record)
        names = [img['filename'] for img in record['lens_images']]
        self.assertEqual(names, ['fwlq101.bin', 'fwlq102.bin'])
        self.assertEqual(record['lens_images'][0]['file_crc_trailer'], 0x1CA0)
        self.assertEqual(record['lens_images'][0]['lom_crc_header'], 0x2668)
        self.assertEqual(record['lens_images'][1]['file_crc_trailer'], 0x1F20)
        self.assertEqual(record['lens_images'][1]['lom_crc_header'], 0xFEA2)

    def test_crc16_ccitt_reference_vector(self):
        self.assertEqual(checker.crc16_ccitt_zero(b'123456789'), 0x31C3)

    def test_builder_matches_published_html(self):
        rendered = builder.render(builder.load_record())
        published = (ROOT / 'reports/lens-firmware-update.html').read_text(encoding='utf-8')
        self.assertIn('01 STANDARD PRIME', rendered)
        self.assertIn('02 STANDARD ZOOM', rendered)
        # Body up to chrome:bottom or full html may have chrome synced after build_all.
        self.assertEqual(rendered.split('<!-- chrome:bottom -->')[0], published.split('<!-- chrome:bottom -->')[0])


if __name__ == '__main__':
    unittest.main()
