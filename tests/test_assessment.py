import unittest
import tempfile
import sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from apk_sentinel.assessment import compare_results, sarif
from apk_sentinel.external_tools import run_tool


class AssessmentTests(unittest.TestCase):
    def test_runtime_links_require_exact_observed_url(self):
        from apk_sentinel.runtime_links import correlate_urls
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'Client.java').write_text('String u = "https://example.test/api";\nString other = "https://example.test/private";', encoding='utf-8')
            result = correlate_urls(root, [{'id': 'capture-1', 'requests': [{'url': 'https://example.test/api'}]}])
            self.assertEqual(len(result['links']), 1)
            self.assertEqual(result['links'][0]['requests'][0]['capture_id'], 'capture-1')
            self.assertEqual(result['links'][0]['line'], 1)
            self.assertEqual(correlate_urls(root, [])['links'], [])

    def result(self, findings, permissions=()):
        return {'profile': {'package_name': 'test.app', 'sha256': 'demo', 'permissions': list(permissions)}, 'findings': findings}

    def test_release_delta_and_ci_output(self):
        finding = {'rule_id': 'debug', 'location': 'manifest', 'severity': 'high', 'title': 'Debug', 'description': 'Debug enabled', 'evidence': 'true'}
        before = self.result([])
        after = self.result([finding], ['android.permission.CAMERA'])
        delta = compare_results(before, after)
        self.assertEqual(delta['introduced'], [finding])
        self.assertEqual(delta['permissions_added'], ['android.permission.CAMERA'])
        self.assertEqual(sarif(after)['runs'][0]['results'][0]['level'], 'error')
        after['profile']['package_name'] = 'other.app'
        with self.assertRaises(ValueError): compare_results(before, after)

    def test_missing_signing_tool_does_not_claim_unsigned(self):
        with patch.dict('os.environ', {}, clear=True), patch('shutil.which', return_value=None):
            self.assertEqual(run_tool('apksigner', 'demo.apk')['status'], 'unavailable')
