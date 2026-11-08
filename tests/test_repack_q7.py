"""Exercise guarded repacking and private output rollback."""
import json
import struct
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from decode_segments import HEADER, decode_segment
from repack_q7 import PRIVATE, footer_check, pack_bits, patch_plan, private_output, rebuild_stream, write_outputs


def fixture(capacity=2):
    leaves=[(x<<2)|3 for x in (65,66,88)]+[0x80f,0x403,0x403,0x403,0x403]
    table=struct.pack('<9I',(3<<11)|4,*[(3<<15)|x for x in leaves])
    distance=struct.pack('<I',3)
    body=bytearray();blocks=[]
    for size,bits in ((1,'000100'),(3,'011100')):
        start=len(body)
        body+=HEADER.pack(2,size,capacity,len(table),4)+table+distance+pack_bits(bits,capacity)
        blocks.append(dict(file_offset=start,file_end=len(body)))
    return bytes(body),dict(blocks=blocks)


class RepackTests(unittest.TestCase):
    def test_private_output_boundary(self):
        expected=PRIVATE/'not-created-by-unit-test'
        self.assertEqual(private_output(expected),expected.resolve())
        for path in (PRIVATE,PRIVATE/'..'/'analysis'/'repack-output',PRIVATE.parent/'public-output'):
            with self.assertRaises(ValueError): private_output(path)

    def test_lossless_tokens_and_cross_block_repair(self):
        source,segment=fixture()
        encoded,changed,tokens=rebuild_stream(source,segment,b'AAAA')
        self.assertEqual(encoded,source);self.assertFalse(changed);self.assertEqual(tokens,4)
        encoded,changed,_=rebuild_stream(source,segment,b'BAAA')
        self.assertEqual([c['block'] for c in changed],[0,1])
        decoded,_=decode_segment(encoded,dict(file_offset=0,file_size=len(encoded),virtual_address=0x1000,memory_size=4))
        self.assertEqual(decoded,b'BAAA')

    def test_missing_literal_and_capacity_rejected(self):
        source,segment=fixture()
        with self.assertRaisesRegex(ValueError,'absent from table'):
            rebuild_stream(source,segment,b'\xffAAA')
        source,segment=fixture(1)
        with self.assertRaisesRegex(ValueError,'slot has 1'):
            rebuild_stream(source,segment,b'BAAA')

    def test_guarded_patch_plan(self):
        regions=[('code',0x1000,bytearray(b'abcd'))]
        patch=dict(va='0x1001',expected_hex='62',replacement_hex='42')
        self.assertEqual(patch_plan([patch],regions),[('code',0x1001,b'B')])
        for changes in ({'va':'0x2000'},{'expected_hex':'00'},{'replacement_hex':'4243'},{'unexpected':1}):
            with self.assertRaises(ValueError): patch_plan([{**patch,**changes}],regions)
        with self.assertRaisesRegex(ValueError,'overlapping'): patch_plan([patch,patch],regions)

    def test_footer_sum_excludes_footer(self):
        data=bytes(range(256))+b'ORION\0\0\0KB538\0\0\x0077690\0\0\0'+struct.pack('<I',32640)+bytes((1,1,23,10))
        result=footer_check(data)
        self.assertTrue(result['sum_matches'])
        self.assertEqual(result['identifiers'],['ORION','KB538','77690'])
        self.assertFalse(footer_check(b'\xff'+data[1:])['sum_matches'])
        self.assertTrue(footer_check(data[:-1]+b'\xff')['sum_matches'])


class WriteOutputsTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        private = Path(temporary.name)
        private_patch = patch('repack_q7.PRIVATE', private)
        private_patch.start()
        self.addCleanup(private_patch.stop)
        self.output = private / 'candidate'
        self.package = b'candidate bytes'
        self.elf = b'expanded bytes'
        self.report = {'byte_identical': True}

    def assert_output(self, output):
        self.assertEqual((output / 'research-update.bin').read_bytes(), self.package)
        self.assertEqual((output / 'analysis-expanded.elf').read_bytes(), self.elf)
        self.assertEqual(json.loads((output / 'repack-report.json').read_bytes()), self.report)

    def test_success_and_existing_output_preserved(self):
        real_open = Path.open
        opened = []

        def record_open(path, mode, **kwargs):
            opened.append((path.name, mode))
            return real_open(path, mode, **kwargs)

        with patch.object(Path, 'open', record_open):
            write_outputs(self.output, self.package, self.elf, self.report)
        self.assertEqual(opened, [
            ('research-update.bin', 'xb'),
            ('analysis-expanded.elf', 'xb'),
            ('repack-report.json', 'xb'),
        ])
        with self.assertRaisesRegex(ValueError, 'must not exist'):
            write_outputs(self.output, b'replacement', b'replacement', {})
        self.assert_output(self.output)

    def test_partial_second_write_rolls_back_and_allows_retry(self):
        real_open = Path.open
        failure = OSError('injected write failure')

        for short_write in (False, True):
            with self.subTest(short_write=short_write):
                output = self.output.with_name(f'candidate-{short_write}')

                @contextmanager
                def fail_open(path, mode, **kwargs):
                    with real_open(path, mode, **kwargs) as stream:
                        if path.name != 'analysis-expanded.elf':
                            yield stream
                            return

                        def incomplete_write(data):
                            written = stream.write(data[:2])
                            if not short_write:
                                raise failure
                            return written

                        partial = Mock(wraps=stream)
                        partial.write.side_effect = incomplete_write
                        yield partial

                with patch.object(Path, 'open', fail_open):
                    if short_write:
                        with self.assertRaisesRegex(OSError, 'short write for analysis-expanded.elf'):
                            write_outputs(output, self.package, self.elf, self.report)
                    else:
                        with self.assertRaises(OSError) as caught:
                            write_outputs(output, self.package, self.elf, self.report)
                        self.assertIs(caught.exception, failure)
                self.assertFalse(output.exists())
                write_outputs(output, self.package, self.elf, self.report)
                self.assert_output(output)

    def test_exclusive_open_collision_preserves_foreign_file(self):
        real_open = Path.open
        foreign = self.output / 'analysis-expanded.elf'

        def collide(path, mode, **kwargs):
            if path == foreign:
                with real_open(foreign, 'xb') as stream:
                    stream.write(b'foreign')
            return real_open(path, mode, **kwargs)

        with patch.object(Path, 'open', collide), self.assertRaises(FileExistsError):
            write_outputs(self.output, self.package, self.elf, self.report)
        self.assertEqual(list(self.output.iterdir()), [foreign])
        self.assertEqual(foreign.read_bytes(), b'foreign')


if __name__=='__main__': unittest.main()
