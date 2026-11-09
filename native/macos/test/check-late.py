#!/usr/bin/env python3
"""Isolated native loader regression; reports booleans and counters only."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve()
results = []
with tempfile.TemporaryDirectory(prefix='claude-native-late-') as temp:
    directory = Path(temp)
    for mode in ('ordinary', 'invalid-region'):
        marker = directory / (mode + '.txt')
        marker.write_text('before\n')
        inode = marker.stat().st_ino
        future = directory / (mode + '.dylib')
        shutil.copy2(build / 'late-consumer.dylib', future)
        env = {
            'PATH': '/usr/bin:/bin', 'HOME': str(directory),
            'TZ': 'America/New_York', 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
        }
        if mode == 'invalid-region':
            env.pop('TZ')
        command = [str(build / 'late-fixture'), str(build / 'libclaude-wrapper.dylib'),
                   str(build / 'late-consumer.dylib'), str(future), str(marker)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=20)
        expected_exit = 1 if mode == 'invalid-region' else 0
        assert result.returncode == expected_exit, (mode, result.returncode, result.stderr)
        assert marker.stat().st_ino == inode
        record = {'mode': mode, 'exit': result.returncode, 'sameHostInode': True}
        if mode == 'invalid-region':
            assert marker.read_text() == 'before\n'
            assert 'activation=22 ' in result.stderr and 'written=0 ' in result.stderr
            record.update({'invalidRegionRejectedBeforeWrites': True})
        else:
            assert marker.read_text() == 'native host I/O\n'
            assert not result.stderr
            record.update(json.loads(result.stdout))
            record['hostReadChangedContent'] = True
        results.append(record)
print(json.dumps(results, indent=2))
