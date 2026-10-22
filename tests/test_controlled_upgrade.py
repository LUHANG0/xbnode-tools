import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('controlled_upgrade',Path(__file__).resolve().parents[1]/'tools/upgrade_node36.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)

class ControlledUpgradeTests(unittest.TestCase):
    def test_atomic_program_failure_preserves_original_and_success_is_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);target=root/'program';target.write_bytes(b'old');new=root/'new';new.write_bytes(b'candidate')
            with patch.object(u.os,'chown'):
                with self.assertRaises(FileNotFoundError):u.atomic_program(root/'missing',target)
                self.assertEqual(target.read_bytes(),b'old')
                u.atomic_program(new,target)
            self.assertEqual(target.read_bytes(),b'candidate')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o755)
            self.assertEqual(list(root.glob('.node36-upgrade-*')),[])

    def test_backup_verifies_config_permissions_and_old_binary_without_extraction(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);binary=root/'program';binary.write_bytes(b'old program');config=root/'config';config.mkdir();service=root/'service';service.write_text('unit')
            env=config/'credentials.env';env.write_text('synthetic secret only');env.chmod(0o600);dest=root/'backup';dest.mkdir()
            with patch.object(u,'BINARY',binary),patch.object(u,'CONFIG',config),patch.object(u,'SERVICE',service),patch.object(u,'DROPINS',root/'dropins'),patch.object(u,'OLD',hashlib.sha256(binary.read_bytes()).hexdigest()):
                baseline=u.tree_state();archive,old=u.backup(dest,baseline)
                self.assertEqual(old.read_bytes(),binary.read_bytes())
                self.assertEqual(stat.S_IMODE(archive.stat().st_mode),0o600)
                self.assertEqual(u.tree_state(),baseline)
                (config/'unexpected-link').symlink_to(service)
                with self.assertRaises(RuntimeError):u.tree_state()
