import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('prepare_dependencies',Path(__file__).resolve().parents[1]/'tools/prepare_dependencies.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class DependencyPreparationTests(unittest.TestCase):
    def test_clean_cache_downloads_pinned_source_without_changing_original_locks(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);source=root/'source';source.mkdir();cache=root/'immutable-cache';cache.mkdir();patches=root/'patches';patches.mkdir()
            (source/'go.mod').write_text('module synthetic\n');(source/'go.sum').write_text('synthetic hash\n')
            original=b'original';(cache/'entry.go').write_bytes(original);(patches/'local').mkdir();(patches/'local/entry.go').write_bytes(b'modified')
            (patches/'lock.json').write_text(json.dumps([{'module':'example.com/upstream','version':'v1.0.0','file':'local/entry.go','path':'entry.go','base_sha256':hashlib.sha256(original).hexdigest()}]))
            metadata={'Path':'example.com/upstream','Version':'v1.0.0'}
            responses=[json.dumps(metadata),json.dumps(dict(metadata,Dir=str(cache)))]
            with patch.object(p.subprocess,'check_output',side_effect=responses) as calls,patch.object(p.subprocess,'run'):
                result=p.prepare(source,'synthetic-go',patches)
            self.assertEqual(calls.call_args_list[1].args[0][1:4],['mod','download','-json'])
            self.assertEqual((cache/'entry.go').read_bytes(),original)
            self.assertEqual((source/'maintenance-dependencies/local/entry.go').read_bytes(),b'modified')
            self.assertEqual((source/'go.mod').read_text(),'module synthetic\n')
            self.assertEqual((source/'maintenance.mod').read_bytes(),(source/'go.mod').read_bytes())
            self.assertEqual(result,(source/'maintenance.mod').resolve())
