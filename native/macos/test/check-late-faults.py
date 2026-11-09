#!/usr/bin/env python3
"""Only the test dylib exposes fault controls; readiness is never acknowledged."""
from pathlib import Path
import json
import os
import struct
import subprocess
import sys
import tempfile

build = Path(sys.argv[1]).resolve()
fields = ['abi_version','struct_size','activation_error','self_test_mask','image_callbacks','images_examined','unsupported_images','parse_failures','slots_matched','stores_performed','slots_written','slots_already_bound','slots_failed','protection_failures','restoration_failures','verification_failures','main_slots_matched','main_slots_written','main_slots_failed','active']
records = []
with tempfile.TemporaryDirectory(prefix='claude-native-fault-') as temp:
    for mode in (1, 2, 3):
        audit_r, audit_w = os.pipe()
        ready_r, ready_w = os.pipe()
        constructor_r, constructor_w = os.pipe()
        env = {
            'PATH': '/usr/bin:/bin', 'HOME': temp,
            'TZ': 'America/New_York', 'LANG': 'en_US.UTF-8', 'LC_ALL': 'en_US.UTF-8',
            'CLAUDE_WRAPPER_INIT_OWNER': 'bun', 'CLAUDE_WRAPPER_READY_FD': str(ready_w),
            'CLAUDE_WRAPPER_TEST_CONSTRUCTOR_FD': str(constructor_w),
        }
        command = [str(build / 'late-fault-fixture'), str(build / 'libclaude-wrapper-test.dylib'),
                   str(build / 'late-consumer.dylib'), str(mode), str(audit_w)]
        try:
            result = subprocess.run(command, env=env, pass_fds=(audit_w, ready_w, constructor_w),
                                    capture_output=True, timeout=15)
            for descriptor in (audit_w, ready_w, constructor_w): os.close(descriptor)
            data = os.read(audit_r, 160)
            assert len(data) == 160, (mode, result.returncode, result.stderr)
            status = dict(zip(fields, struct.unpack('<20Q', data)))
            assert os.read(ready_r, 1) == b''
            assert os.read(constructor_r, 1) == b''
        finally:
            for descriptor in (audit_r, ready_r, constructor_r): os.close(descriptor)
        assert result.returncode == (0 if mode == 1 else 126), (mode, result.returncode, result.stderr)
        if mode == 1:
            assert status['activation_error'] != 0 and status['protection_failures'] > 0
            assert status['stores_performed'] == status['slots_written'] == 0
        elif mode == 2:
            assert status['restoration_failures'] > 0 and status['stores_performed'] > 0
        else:
            assert status['protection_failures'] > 0 and status['slots_failed'] > 0
        records.append({'mode': mode, 'exit': result.returncode, 'noReadyAck': True,
                        'constructorNotRun': True, 'storesPerformed': status['stores_performed'],
                        'protectionFailures': status['protection_failures'],
                        'restorationFailures': status['restoration_failures']})
exports = subprocess.check_output(['nm', '-gU', str(build / 'libclaude-wrapper.dylib')], text=True)
assert 'cw_rebind_test_set_fault' not in exports
print(json.dumps({'productionHasNoFaultControls': True, 'faultRuns': records}, indent=2))
