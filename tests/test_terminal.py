"""Exercise the actual controlling terminal, without a server or panel."""
import errno
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import sys
import time
import unittest

BASE = Path(__file__).resolve().parents[1]
LOAD = f"""
import importlib.util
spec = importlib.util.spec_from_file_location('xbnode', {str(BASE / 'xbnode.py')!r})
xb = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xb)
"""


class TerminalTests(unittest.TestCase):
    def interact(self, script, exchanges):
        pid, master = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [sys.executable, '-c', LOAD + script])
        output = bytearray()
        deadline = time.monotonic() + 15

        def read():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([master], [], [], max(0, remaining))[0]:
                self.fail('Timed out waiting for the terminal: ' + repr(bytes(output)))
            try:
                chunk = os.read(master, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    return False
                raise
            output.extend(chunk)
            return bool(chunk)

        try:
            for prompt, answer in exchanges:
                while prompt.encode() not in output:
                    if not read():
                        self.fail('Terminal ended before prompt: ' + repr(bytes(output)))
                os.write(master, answer.encode() + b'\n')
            while read():
                pass
            _, status = os.waitpid(pid, 0)
            pid = None
            self.assertEqual(os.waitstatus_to_exitcode(status), 0, bytes(output).decode())
            return bytes(output).decode()
        finally:
            os.close(master)
            if pid is not None:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(pid, 0)

    def test_default_unicode_and_confirmation_use_real_tty(self):
        output = self.interact("""
ui = xb.Terminal()
assert ui.ask('中文输入') == '你好'
assert ui.ask('选项', '1') == '1'
assert ui.confirm('确认继续')
print('TTY_OK', flush=True)
""", [('中文输入：', '你好'), ('选项 [1]：', ''), ('确认继续，输入 yes 继续 [no]：', 'yes')])
        self.assertIn('TTY_OK', output)

    def test_secret_input_uses_real_tty_without_echo(self):
        secret = 'SYNTHETIC-tty-secret'
        output = self.interact("""
ui = xb.Terminal()
assert ui.ask('测试密钥', secret=True) == 'SYNTHETIC-tty-secret'
print('SECRET_OK', flush=True)
""", [('测试密钥：', secret)])
        self.assertIn('SECRET_OK', output)
        self.assertNotIn(secret, output)

    def test_real_menu_with_redirected_stdin_can_exit(self):
        output = self.interact("""
import os, tempfile
from pathlib import Path
xb.sys.stdin = open(os.devnull)
with tempfile.TemporaryDirectory() as directory:
    xb.ROOT = Path(directory)
    xb.write_json(xb.ROOT / 'settings.json', {'repo': 'owner/repo'})
    xb.write_json(xb.ROOT / 'node-41/node.json', {
        'node_id': 41, 'installed': True, 'release': 'v0.2.3',
        'node_version': 'synthetic-version',
        'spec': {'label': 'VLESS', 'port': 30000, 'transport': 'tcp'}})
    xb.active = lambda node_id: False
    xb.require_host = lambda: None
    xb.sys.argv = ['xbnode']
    xb.main()
print('MENU_OK', flush=True)
""", [('请选择 [0]：', '0')])
        self.assertIn('1. 添加节点', output)
        self.assertIn('1. 添加节点\r\n2. 脱敏日志\r\n3. 启停/重启', output)
        self.assertIn('节点 ID：41\r\n协议：VLESS\r\n端口：30000\r\n传输：tcp', output)
        self.assertIn('工具版本：v0.2.3\r\n节点程序：synthetic-version\r\n状态：已停止', output)
        self.assertIn('MENU_OK', output)

    def test_missing_controlling_tty_has_actionable_message(self):
        result = subprocess.run([sys.executable, '-c', LOAD + """
try:
    xb.Terminal()
except xb.Error as error:
    print(str(error))
else:
    raise AssertionError('A detached session must not have a controlling terminal')
"""], start_new_session=True, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('控制终端', result.stdout)
        self.assertIn('/root/install-xbnode.sh', result.stdout)


if __name__ == '__main__':
    unittest.main()
