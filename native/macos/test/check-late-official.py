#!/usr/bin/env python3
"""Actual official --help only; clean credentials/config and loopback-only guard."""
from pathlib import Path
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
build = root / 'native/macos/build'
preload = Path(__file__).resolve().with_name('late-preload.cjs')
account = pwd.getpwuid(os.getuid())
results = []
output = root / 'target/compat/late-native-region'
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='claude-native-official-') as temp:
    directory = Path(temp)
    for version in ('2.1.169', '2.1.319'):
        binary = root / f'target/compat/claude-code-{version}/package/claude'
        assert binary.is_file(), 'Official client fixture is missing; no download is attempted.'
        before_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        home = directory / version
        home.mkdir()
        config = home / 'config'
        config.mkdir()
        marker = home / 'marker'
        marker.write_text('before\n')
        inode = marker.stat().st_ino
        future = home / 'future-consumer.dylib'
        shutil.copy2(build / 'late-consumer.dylib', future)
        env = {
            'PATH': '/usr/bin:/bin', 'HOME': str(home), 'CLAUDE_CONFIG_DIR': str(config),
            'ANTHROPIC_API_KEY': 'sk-ant-invalid-local-native-test',
            'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1', 'DO_NOT_TRACK': '1',
            'USER': account.pw_name, 'HOSTNAME': subprocess.check_output(['/bin/hostname'], text=True).strip(),
            'SHELL': '/bin/zsh', 'TZ': 'America/New_York', 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
            'CLAUDE_WRAPPER_INIT_OWNER': 'bun',
            'CLAUDE_WRAPPER_NATIVE_LIBRARY': str(build / 'libclaude-wrapper.dylib'),
            'CLAUDE_WRAPPER_TEST_EXISTING': str(build / 'late-consumer.dylib'),
            'CLAUDE_WRAPPER_TEST_FUTURE': str(future), 'CLAUDE_WRAPPER_TEST_IO': str(marker),
            'BUN_OPTIONS': f'--preload {preload}',
        }
        command = [str(root / 'native/egress/build/socket-guard'), '--ipv4', '--identity-guard', '65534', str(binary), '--help']
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        (output / f'{version}.stdout').write_text(result.stdout)
        (output / f'{version}.stderr').write_text(result.stderr)
        assert result.returncode == 0, (version, result.returncode, result.stderr)
        assert result.stdout.startswith('Usage: claude')
        probe = json.loads(next(line.removeprefix('NATIVE_PRODUCTION_RESULT ') for line in result.stderr.splitlines() if line.startswith('NATIVE_PRODUCTION_RESULT ')))
        assert marker.stat().st_ino == inode and marker.read_text() == 'native official I/O\n'
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == before_hash
        signature = subprocess.run(['codesign', '--verify', '--strict', str(binary)], capture_output=True)
        assert signature.returncode == 0
        results.append({'version': version, 'exit': 0, 'officialBytesUnchanged': True,
                        'strictSignatureValid': True, 'hostSameInodeAndContent': True, **probe})
(output / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results, indent=2))
