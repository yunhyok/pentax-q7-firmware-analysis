"""A changed pathname must not replace the bytes authenticated for replay."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_isp_registers as loader


class PinnedElfTests(unittest.TestCase):
    def test_loader_uses_verified_snapshot_after_path_changes(self):
        original = b'original ELF bytes'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'analysis.elf'
            path.write_bytes(original)
            def project(source, **options):
                path.write_bytes(b'changed after verification')
                self.assertIsInstance(source, io.BytesIO)
                self.assertEqual(source.read(), original)
                self.assertEqual(options, {'auto_load_libs': False})
                return 'verified project'
            with patch.object(loader, 'ELF_SHA256', hashlib.sha256(original).hexdigest()), \
                 patch.dict(sys.modules, angr=SimpleNamespace(Project=project)):
                self.assertEqual(loader.load_project(path), 'verified project')
            self.assertNotEqual(path.read_bytes(), original)

    def test_wrong_digest_never_reaches_execution_engine(self):
        engine = Mock()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'wrong.elf'
            path.write_bytes(b'not the original Q7 image')
            with patch.dict(sys.modules, angr=engine):
                with self.assertRaisesRegex(ValueError, 'SHA-pinned'):
                    loader.load_project(path)
            engine.Project.assert_not_called()


if __name__ == '__main__':
    unittest.main()
