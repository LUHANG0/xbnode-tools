import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    def execute(self, corrupt=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = root / "fixtures"
            fixture.mkdir()
            marker = root / "executed"
            manager = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('verified')\n"
            (fixture / "xbnode.py").write_text(manager)
            (fixture / "manifest.json").write_text(json.dumps({"release": "v0.1.0"}))
            hashes = "".join(hashlib.sha256((fixture / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in ("xbnode.py", "manifest.json"))
            (fixture / "SHA256SUMS").write_text(hashes)
            if corrupt:
                (fixture / "xbnode.py").write_text(manager + "# tampered\n")
            tools = root / "bin"
            tools.mkdir()
            stubs = {
                "id": "#!/bin/sh\nprintf '0\\n'\n",
                "uname": "#!/bin/sh\nprintf 'Linux\\n'\n",
                "curl": "#!/usr/bin/env python3\nimport os,sys,shutil\nfrom pathlib import Path\na=sys.argv[1:]; i=a.index('-o'); name=a[i-1].rsplit('/',1)[1]; shutil.copyfile(Path(os.environ['XBN_FIXTURES'])/name,a[i+1])\n",
                "sha256sum": "#!/usr/bin/env python3\nimport sys,hashlib\nfrom pathlib import Path\ns=sys.stdin.read().strip(); expected,name=s.split(None,1); sys.exit(0 if hashlib.sha256(Path(name).read_bytes()).hexdigest()==expected else 1)\n",
            }
            for name, text in stubs.items():
                path = tools / name
                path.write_text(text)
                path.chmod(0o755)
            result = subprocess.run(["bash", str(BASE / "install.sh"), "--repo", "owner/repo"], capture_output=True, text=True, timeout=10,
                                    env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ["PATH"], XBN_FIXTURES=str(fixture)))
            return result.returncode, marker.exists()

    def test_validated_payload_can_execute(self):
        self.assertEqual(self.execute(), (0, True))

    def test_modified_payload_never_executes(self):
        code, executed = self.execute(corrupt=True)
        self.assertNotEqual(code, 0)
        self.assertFalse(executed)


if __name__ == "__main__":
    unittest.main()
