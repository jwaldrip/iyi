import subprocess
import unittest
from unittest.mock import patch

from proof.preflight_oracle import check_nsupdate


class NsupdatePreflightTests(unittest.TestCase):
    def run_probe(self, response):
        calls = []

        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[-1] == '-V':
                return subprocess.CompletedProcess(argv, 0, stdout='nsupdate test\n', stderr='')
            if isinstance(response, Exception):
                raise response
            return response

        with patch('proof.preflight_oracle.shutil.which', return_value='/test/nsupdate'), patch(
            'proof.preflight_oracle.subprocess.run', side_effect=run
        ):
            result = check_nsupdate()
        return result, calls

    def test_parses_without_sending_update(self):
        (ok, _), calls = self.run_probe(subprocess.CompletedProcess([], 0, stdout='', stderr=''))
        self.assertTrue(ok)
        probe = calls[1][1]['input']
        self.assertIn('update add probe.test. 60 IN HTTPS 1 .', probe)
        self.assertNotIn('send', probe.splitlines())
        self.assertNotIn('server ', probe)

    def test_rejects_parser_failure(self):
        (ok, detail), _ = self.run_probe(
            subprocess.CompletedProcess([], 1, stdout='', stderr='unknown class/type')
        )
        self.assertFalse(ok)
        self.assertIn('unknown class/type', detail)

    def test_rejects_timeout(self):
        (ok, detail), _ = self.run_probe(subprocess.TimeoutExpired('nsupdate', 5))
        self.assertFalse(ok)
        self.assertIn('timed out', detail)


if __name__ == '__main__':
    unittest.main()
