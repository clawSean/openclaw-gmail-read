import argparse
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'activation_preflight.py'
SPEC = importlib.util.spec_from_file_location('activation_preflight', SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(preflight)


class ActivationPreflightTests(unittest.TestCase):
    def _fixture(self, temp: pathlib.Path, *, ready: bool = True) -> argparse.Namespace:
        project = temp / 'project'
        plugin = project / 'mailreef-plugin' / 'src'
        plugin.mkdir(parents=True)
        broker = project / 'mailreef_broker.py'
        broker.write_text('synthetic broker\n')
        digest = hashlib.sha256(broker.read_bytes()).hexdigest()
        (plugin / 'index.js').write_text(f'const EXPECTED_BROKER_SHA256 = "{digest}";\n')

        credentials = temp / 'credentials'
        read_dir = credentials / 'mailreef-sean'
        read_dir.mkdir(parents=True, mode=0o700)
        read_dir.chmod(0o700)
        client = {'installed': {'client_id': 'read-client', 'client_secret': 'synthetic'}}
        token = {'refresh_token': 'synthetic', 'scope': ' '.join(sorted(preflight.SCOPES))}
        for name, payload in (('client_secret.json', client), ('token.json', token)):
            path = read_dir / name
            path.write_text(json.dumps(payload))
            path.chmod(0o600)
        registry = credentials / 'mailreef-accounts.json'
        registry.write_text(json.dumps({'accounts': [{
            'label': 'sean', 'credential_dir': str(read_dir), 'can_read': False,
        }]}))
        registry.chmod(0o600)

        oc = temp / 'openclaw.json'
        oc.write_text(json.dumps({'plugins': {'entries': {'mailreef': {
            'enabled': False,
            'llm': {
                'allowModelOverride': True,
                'allowedModels': [preflight.MODEL],
                'allowedCompletionModels': [preflight.MODEL],
            },
            'config': {
                'defaultAccount': 'sean',
                'macBrokerScriptPath': str(broker),
                'summarizerModel': preflight.MODEL,
                'postDetectorModel': preflight.MODEL,
            },
        }}}}))
        if not ready:
            (read_dir / 'token.json').unlink()
        return argparse.Namespace(
            phase='prepare', account='sean', project_root=project,
            credential_base=credentials, openclaw_config=oc,
        )

    def test_ready_fixture_passes_without_exposing_secrets(self):
        with tempfile.TemporaryDirectory() as raw:
            result = preflight.run_checks(self._fixture(pathlib.Path(raw)))
        self.assertEqual(result['status'], 'ready')
        encoded = json.dumps(result)
        self.assertNotIn('read-client', encoded)
        self.assertNotIn('synthetic', encoded)

    def test_missing_token_blocks(self):
        with tempfile.TemporaryDirectory() as raw:
            result = preflight.run_checks(self._fixture(pathlib.Path(raw), ready=False))
        self.assertEqual(result['status'], 'blocked')
        failed = {item['name'] for item in result['checks'] if not item['ok']}
        self.assertIn('OAuth token private', failed)

    def test_secondary_account_prepare_and_live_routing(self):
        with tempfile.TemporaryDirectory() as raw:
            args = self._fixture(pathlib.Path(raw))
            credentials = args.credential_base
            sean_dir = credentials / 'mailreef-sean'
            jpop_dir = credentials / 'mailreef-jpop'
            jpop_dir.mkdir(mode=0o700)
            jpop_dir.chmod(0o700)
            for name in ('client_secret.json', 'token.json'):
                target = jpop_dir / name
                target.write_bytes((sean_dir / name).read_bytes())
                target.chmod(0o600)
            registry_path = credentials / 'mailreef-accounts.json'
            registry = json.loads(registry_path.read_text())
            registry['accounts'].append({'label': 'jpop', 'credential_dir': str(jpop_dir), 'can_read': False})
            registry_path.write_text(json.dumps(registry))
            registry_path.chmod(0o600)
            config = json.loads(args.openclaw_config.read_text())
            entry = config['plugins']['entries']['mailreef']
            entry['enabled'] = True
            entry['config']['allowedAccounts'] = ['sean']
            args.openclaw_config.write_text(json.dumps(config))
            args.account = 'jpop'
            args.phase = 'account_prepare'
            self.assertEqual(preflight.run_checks(args)['status'], 'ready')

            registry['accounts'][-1]['can_read'] = True
            registry_path.write_text(json.dumps(registry))
            registry_path.chmod(0o600)
            entry['config']['allowedAccounts'].append('jpop')
            args.openclaw_config.write_text(json.dumps(config))
            args.phase = 'live'
            self.assertEqual(preflight.run_checks(args)['status'], 'ready')


if __name__ == '__main__':
    unittest.main()
