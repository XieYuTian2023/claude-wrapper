#!/usr/bin/env python3
"""Run the process-group terminal test in its own controlling terminal."""
import fcntl
import os
from pathlib import Path
import pty
import select
import subprocess
import termios
import time

ROOT=Path(__file__).resolve().parents[2]
master,slave=pty.openpty()
def session():
    os.setsid()
    fcntl.ioctl(0,termios.TIOCSCTTY,0)
child=subprocess.Popen(["cargo","test","--offline","terminal_handoff_fast_exit_and_native_input",
    "--","--ignored","--nocapture","--test-threads=1"],cwd=ROOT,
    stdin=slave,stdout=slave,stderr=slave,preexec_fn=session)
os.close(slave)
data=b""
sent=False
deadline=time.monotonic()+30
try:
    while child.poll() is None and time.monotonic()<deadline:
        if select.select([master],[],[],0.2)[0]:
            try:
                chunk=os.read(master,65536)
            except OSError:
                break
            data+=chunk
            if not sent and b"PTY_NATIVE_INPUT_READY" in data:
                os.write(master,b"hello\n")
                sent=True
    child.wait(timeout=2)
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
    os.close(master)
print(data.decode(errors="replace"))
assert sent and child.returncode==0, "terminal handoff regression failed"
