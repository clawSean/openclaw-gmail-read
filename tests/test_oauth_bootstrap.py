import importlib.util
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts' / 'bootstrap_gmail_read_oauth.py'
SPEC = importlib.util.spec_from_file_location('gmail_oauth_bootstrap', SCRIPT)
oauth = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(oauth)


class OAuthBootstrapTests(unittest.TestCase):
    def test_scopes_are_exact_and_read_only(self):
        scopes = oauth._validate_scopes(' '.join(oauth.SCOPES))
        self.assertEqual(scopes, set(oauth.SCOPES))
        with self.assertRaises(ValueError):
            oauth._validate_scopes(' '.join((*oauth.SCOPES, 'https://www.googleapis.com/auth/gmail.send')))
        with self.assertRaises(ValueError):
            oauth._validate_scopes('openid https://www.googleapis.com/auth/userinfo.email')

    def test_client_must_be_desktop_oauth(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'client.json'
            path.write_text(json.dumps({'web': {'client_id': 'id', 'client_secret': 'secret'}}))
            with self.assertRaises(ValueError):
                oauth._load_client(path)
            path.write_text(json.dumps({'installed': {'client_id': 'id', 'client_secret': 'secret'}}))
            self.assertEqual(oauth._load_client(path)['client_id'], 'id')

    def test_private_json_write_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            path = pathlib.Path(temp) / 'credentials' / 'token.json'
            oauth._atomic_private_json(path, {'refresh_token': 'not-a-real-token'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(path.read_text())['refresh_token'], 'not-a-real-token')

    def test_read_client_must_differ_from_send_client(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            send = base / 'gmail-send-sean' / 'client_secret.json'
            send.parent.mkdir()
            send.write_text(json.dumps({'installed': {'client_id': 'shared-client'}}))
            with self.assertRaises(ValueError):
                oauth._assert_distinct_from_send_clients('shared-client', base)
            oauth._assert_distinct_from_send_clients('read-only-client', base)

    def test_cli_requires_expected_email_and_client_path(self):
        with redirect_stderr(StringIO()):
            with self.assertRaises(SystemExit):
                oauth.parse_args([])


if __name__ == '__main__':
    unittest.main()
