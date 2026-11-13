"""Resolve report links from the report's own directory and keep them in the checkout."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import verify_report


class ReportLinkTests(unittest.TestCase):
    def test_root_and_nested_reports_use_document_relative_links(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'reports').mkdir()
            (root / 'assets').mkdir()
            (root / 'assets/site.css').write_text('body {}', encoding='utf-8')
            (root / 'index.html').write_text('<h1 id="home">Home</h1>', encoding='utf-8')
            for name, prefix in [('root.html', ''), ('reports/nested.html', '../')]:
                page = root / name
                page.write_text(f'<link href="{prefix}assets/site.css"><a href="{prefix}index.html#home">Home</a>', encoding='utf-8')
                with self.subTest(page=name), patch.object(verify_report, 'ROOT', root):
                    verify_report.check_page(page)

    def test_nested_report_cannot_escape_checkout_or_use_missing_anchor(self):
        with tempfile.TemporaryDirectory() as folder:
            outer = Path(folder)
            root = outer / 'repo'
            (root / 'reports').mkdir(parents=True)
            (outer / 'outside.html').write_text('outside', encoding='utf-8')
            (root / 'index.html').write_text('<h1 id="home">Home</h1>', encoding='utf-8')
            page = root / 'reports/nested.html'
            for link in ('../../outside.html', '../index.html#missing'):
                page.write_text(f'<a href="{link}">Invalid</a>', encoding='utf-8')
                with self.subTest(link=link), patch.object(verify_report, 'ROOT', root):
                    with self.assertRaises(AssertionError):
                        verify_report.check_page(page)
