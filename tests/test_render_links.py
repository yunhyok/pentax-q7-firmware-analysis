"""Reject valid but incorrectly connected Color Space resources."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from verify_io_followup import validate_render_links


class RenderLinkTests(unittest.TestCase):
    def test_ordered_links_are_pinned(self):
        original = json.loads((ROOT/'analysis/colorspace-render.json').read_text(encoding='utf-8'))
        validate_render_links(original)
        for mutation in ('table', 'widget', 'descriptor', 'line', 'order', 'marker', 'active'):
            changed = deepcopy(original)
            labels, assets = changed['labels'], changed['focus_assets']
            if mutation == 'table': labels[0]['language_table'] = labels[1]['language_table']
            elif mutation == 'widget': labels[0]['widget'] = labels[1]['widget']
            elif mutation == 'descriptor': labels[0]['descriptors'][0] = deepcopy(labels[1]['descriptors'][0])
            elif mutation == 'line': labels[0]['descriptors'][0]['lines'] = deepcopy(labels[1]['descriptors'][0]['lines'])
            elif mutation == 'order': labels.reverse()
            elif mutation == 'marker': assets['marker_tables']['height_u16'] = assets['marker_tables']['logical_width_u16']
            else: assets['active']['srgb'].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                validate_render_links(changed)


if __name__ == '__main__': unittest.main()
