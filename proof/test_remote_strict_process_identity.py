import ctypes
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / '.github/actions/strict-supervisor/src/process_identity.py'
spec = importlib.util.spec_from_file_location('strict_process_identity', SCRIPT)
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


def record(pid, ppid, sec=1, usec=0, state=1):
    data = bytearray(648)
    struct.pack_into('=q', data, 0, sec)
    struct.pack_into('=i', data, 8, usec)
    struct.pack_into('=B', data, 36, state)
    struct.pack_into('=i', data, 40, pid)
    struct.pack_into('=i', data, 560, ppid)
    return bytes(data)


class CensusDecoding(unittest.TestCase):
    def test_invalid_record_size_and_usec(self):
        with self.assertRaises(ValueError):
            identity._records(b'bad')
        with self.assertRaises(ValueError):
            identity._records(record(1, 0, usec=1000000))

    def test_zombie_state(self):
        self.assertEqual(identity._records(record(2, 1, state=5))[0]['state'], 'Z')

    def test_census_self_check_rejects_duplicate_missing_and_wrong_parent(self):
        own = os.getpid()
        parent = os.getppid()
        cases = [
            record(1, 0) + record(own, parent) + record(own, parent),
            record(1, 0),
            record(1, 0) + record(own, parent + 1),
        ]
        for raw in cases:
            with self.subTest(size=len(raw)), patch.object(identity, '_kinfo', return_value=(raw, {})), \
                    patch.object(identity, '_own_birth', return_value='1.000000'):
                with self.assertRaises((ValueError, RuntimeError)):
                    identity._census_darwin()


@unittest.skipUnless(sys.platform == 'darwin', 'requires Darwin kernel')
class DarwinIdentity(unittest.TestCase):
    def test_own_birth_matches_proc_pidinfo(self):
        self.assertEqual(identity._observe_darwin(os.getpid())['birth'], identity._own_birth())

    def test_unreaped_zombie_then_absent(self):
        pid = os.fork()
        if pid == 0:
            import time
            time.sleep(0.25)
            os._exit(0)
        try:
            running = identity._observe_darwin(pid)
            self.assertEqual(running['status'], 'LIVE')
            import time
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                zombie = identity._observe_darwin(pid)
                if zombie.get('state') == 'Z':
                    break
                time.sleep(0.02)
            self.assertEqual(zombie['state'], 'Z')
            self.assertEqual(zombie['birth'], running['birth'])
        finally:
            os.waitpid(pid, 0)
        self.assertEqual(identity._observe_darwin(pid)['status'], 'ABSENT')

    def test_batch_has_pid_one_and_self_without_nulls(self):
        reply = json.loads(subprocess.check_output([sys.executable, str(SCRIPT), '--batch'],
            input=json.dumps({'pids': [os.getpid()], 'census': True}), text=True))
        self.assertNotIn('error', reply['census'])
        rows = reply['census']['rows']
        self.assertTrue(any(row[0] == 1 for row in rows))
        # The batch helper itself, not this test process, is verified by its self-check.
        self.assertTrue(all(all(value is not None for value in row) for row in rows))
        self.assertEqual(reply['identities'][str(os.getpid())]['status'], 'LIVE')
