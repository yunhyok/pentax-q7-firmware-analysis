"""Ensure recorded fixture outputs and evidence relationships cannot drift silently."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import verify_continuation as verify


class ContinuationEvidenceTests(unittest.TestCase):
    def test_replay_and_provenance_mutations(self):
        original = {n:json.loads((ROOT/'analysis'/n).read_text(encoding='utf-8'))
                    for n in ('burn-continuation.json','colorspace-raster.json','burn-finalization.json')}
        verify.verify()
        for mutation in ('program', 'protection', 'extent', 'branch', 'pixel', 'template', 'terminal_status', 'terminal_buffer', 'terminal_extent'):
            docs = deepcopy(original)
            burn,raster,terminal = docs.values()
            if mutation == 'program': burn['bounded_replay']['cases'][0]['aggregate_program_calls'] += 1
            elif mutation == 'protection': burn['bounded_replay']['cases'][5]['protection_skip_count'] -= 1
            elif mutation == 'extent': burn['selected_functions'][0]['candidate_end'] += 4
            elif mutation == 'branch': raster['replay']['cases'][0]['steps'][0]['branch'] = 'word'
            elif mutation == 'pixel': raster['replay']['cases'][0]['steps'][0]['changed_bytes'] += 1
            elif mutation == 'template': raster['context_template']['va'] = raster['duplicate_named_ranges'][0]['va']
            elif mutation == 'terminal_status': terminal['bounded_replay']['cases'][-1]['return_value'] = 1
            elif mutation == 'terminal_buffer': terminal['bounded_replay']['cases'][-1]['requests'][-1]['arguments'][4] = '0x11001414'
            else: terminal['selected_functions'][1]['candidate_end'] += 4
            with self.subTest(mutation=mutation), patch.object(verify,'read',side_effect=docs.__getitem__), self.assertRaises(AssertionError):
                verify.verify()


if __name__ == '__main__': unittest.main()
