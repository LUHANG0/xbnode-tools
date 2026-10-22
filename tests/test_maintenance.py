import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout
spec = importlib.util.spec_from_file_location('xbmaint', Path(__file__).resolve().parents[1] / 'xbnode.py')
xb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xb)

class MaintenanceTests(unittest.TestCase):
    def test_diagnostics_unknown_never_zero_or_raw_secrets(self):
        with tempfile.TemporaryDirectory() as root, patch.object(xb, 'probe_command', return_value=None):
            report = xb.diagnose_service('xboard-node-36.service', 30000, proc=Path(root), sample_seconds=0)
            for key in ('pid', 'cpu_percent_one_core', 'rss_bytes', 'pss_bytes', 'fds', 'loaded_users', 'last_report_at', 'listener_owned'):
                self.assertIsNone(report[key], key)
            self.assertEqual(report['business_connectivity'], 'unknown')
        self.assertEqual(xb.optional_int('[not set]'), None)
        self.assertEqual(xb.optional_int(str(2**64-1)), None)

    def test_diagnostics_extract_allowlisted_fields_only(self):
        secret = 'synthetic-token-must-not-appear'
        log = '\n'.join(json.dumps({'__REALTIME_TIMESTAMP': str(1000000+i), 'MESSAGE': message}) for i,message in enumerate([
            'initial snapshot ready users=7 token='+secret,
            'users updated: +2 -3',
            'report pushed: 2 users, 1 online https://example.com/?token='+secret]))
        def command(*args):
            if args[0] == 'systemctl':
                return 'ActiveState=active\nSubState=running\nMainPID=0\nNRestarts=0\nMemoryCurrent=[not set]\n'
            if args[0] == 'journalctl': return log
        with patch.object(xb, 'probe_command', side_effect=command):
            report = xb.diagnose_service('xbnode-41.service')
        self.assertEqual(report['loaded_users'], 6)
        self.assertIsNotNone(report['last_report_at'])
        self.assertNotIn(secret, json.dumps(report))
        self.assertIsNone(report['cgroup_memory_bytes'])

    def test_retention_protects_running_units_and_all_rollback_edges(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);etc=root/'etc';lib=root/'lib';units=root/'units';proc=root/'proc'
            for p in (etc/'backups',lib/'releases',units,proc): p.mkdir(parents=True)
            with patch.object(xb,'ROOT',etc),patch.object(xb,'LIB',lib),patch.object(xb,'UNITS',units):
                for version in ('v0.1.0','v0.1.1','v0.1.2','v0.2.0','v0.3.0'):
                    (lib/'releases'/version).mkdir()
                for name,version in [('41-a','v0.1.0'),('41-b','v0.1.1'),('41-c','v0.1.2')]:
                    path=etc/'backups'/name;path.mkdir();(path/'node.json').write_text(json.dumps({'node_id':41,'release':version,'previous':None,'last_ready':False}))
                node=etc/'node-41';node.mkdir();(node/'node.json').write_text(json.dumps({'node_id':41,'release':'v0.3.0','previous':str(etc/'backups/41-a')}))
                (units/'xbnode-42.service').write_text('ExecStart='+str(lib/'releases/v0.2.0/xboard-node'))
                plan=xb.retention_plan(1,1,proc=proc)
                self.assertIn(str(etc/'backups/41-b'),plan['candidates'])
                self.assertNotIn(str(etc/'backups/41-a'),plan['candidates'])
                self.assertNotIn(str(lib/'releases/v0.1.0'),plan['candidates'])
                self.assertNotIn(str(lib/'releases/v0.2.0'),plan['candidates'])
                before=sorted(str(p) for p in root.rglob('*'))
                with patch.object(xb,'retention_plan',return_value=plan),redirect_stdout(io.StringIO()): xb.Manager().prune()
                self.assertEqual(before,sorted(str(p) for p in root.rglob('*')))
                class Confirm:
                    def confirm(self, text):return True
                with patch.object(xb,'retention_plan',return_value=plan),redirect_stdout(io.StringIO()): xb.Manager(terminal=Confirm()).prune(apply=True)
                self.assertFalse((etc/'backups/41-b').exists())
                self.assertTrue((etc/'backups/41-a').exists())
                (etc/'backups/41-b').mkdir()
                (etc/'backups/41-b/node.json').write_text('{}')
                (etc/'backups/41-b/node.json').unlink();(etc/'backups/41-b/node.json').symlink_to(node/'node.json')
                with self.assertRaises(xb.Error): xb.retention_plan(1,1,proc=proc)

    def test_retention_refuses_escape_and_keeps_pinned(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);etc=root/'etc';lib=root/'lib';units=root/'units';proc=root/'proc'
            for p in (etc/'backups',etc/'node-1',lib/'releases/v0.1.0',lib/'releases/v0.2.0',units,proc):p.mkdir(parents=True,exist_ok=True)
            node=etc/'node-1/node.json';node.write_text(json.dumps({'node_id':1,'release':'v0.2.0','previous':str(root/'outside')}))
            with patch.object(xb,'ROOT',etc),patch.object(xb,'LIB',lib),patch.object(xb,'UNITS',units):
                with self.assertRaises(xb.Error):xb.retention_plan(1,1,proc=proc)
                node.write_text(json.dumps({'node_id':1,'release':'v0.2.0','previous':None}))
                plan=xb.retention_plan(1,1,('v0.1.0',),proc=proc)
                self.assertEqual(plan['candidates'],[])

    def test_last_successful_snapshot_survives_newer_failed_snapshots(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);etc=root/'etc';lib=root/'lib';units=root/'units';proc=root/'proc'
            for p in (etc/'backups',etc/'node-41',lib/'releases',units,proc):p.mkdir(parents=True,exist_ok=True)
            (etc/'node-41/node.json').write_text(json.dumps({'node_id':41,'release':'v0.2.1','previous':None}))
            for name,ready,version in [('41-a',True,'v0.1.0'),('41-b',False,'v0.1.1'),('41-c',False,'v0.2.0')]:
                p=etc/'backups'/name;p.mkdir();(p/'node.json').write_text(json.dumps({'node_id':41,'release':version,'previous':None,'last_ready':ready}));(lib/'releases'/version).mkdir()
            (lib/'releases/v0.2.1').mkdir()
            with patch.object(xb,'ROOT',etc),patch.object(xb,'LIB',lib),patch.object(xb,'UNITS',units):
                plan=xb.retention_plan(1,1,proc=proc)
            self.assertNotIn(str(etc/'backups/41-a'),plan['candidates'])
            self.assertNotIn(str(lib/'releases/v0.1.0'),plan['candidates'])
            self.assertIn(str(etc/'backups/41-b'),plan['candidates'])
