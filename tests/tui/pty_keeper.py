#!/usr/bin/env python3
"""Keep Darwin's controlling terminal alive until its attributes are inspected."""
import json
import os
import select
import subprocess
import sys


status_fd=int(sys.argv[1])
ack_fd=int(sys.argv[2])
command=sys.argv[3:]


def report(event):
    os.write(status_fd,(json.dumps(event)+"\n").encode())


child=subprocess.Popen(command,stdin=0,stdout=1,stderr=2,close_fds=True)
report({"event":"started","pid":child.pid})
try:
    code=child.wait()
    report({"event":"exit","code":code})
    # The parent reads all terminal attributes before releasing this session
    # leader. Darwin revokes the slave if its controlling session ends first.
    if select.select([ack_fd],[],[],20)[0]:os.read(ack_fd,1)
finally:
    if child.poll() is None:
        child.kill()
        child.wait()
