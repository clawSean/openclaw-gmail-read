#!/usr/bin/env python3
"""Create a Mac-local, Gmail-readonly OAuth token without printing secrets."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import pathlib
import re
import secrets
import sys
import time
import urllib.parse
import urllib.request
import webbrowser
from typing import Any


AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
TOKEN_URI = 'https://oauth2.googleapis.com/token'
TOKENINFO_URI = 'https://www.googleapis.com/oauth2/v1/tokeninfo'
USERINFO_URI = 'https://openidconnect.googleapis.com/v1/userinfo'
SCOPES = (
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
)
SAFE_LABEL_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*$')


def _load_client(path: pathlib.Path) -> dict[str, str]:
    data = json.loads(path.read_text())
    cfg = data.get('installed')
    if not isinstance(cfg, dict):
        raise ValueError('client JSON must be a Google Desktop OAuth client')
    required = ('client_id', 'client_secret')
    if any(not isinstance(cfg.get(key), str) or not cfg[key] for key in required):
        raise ValueError('client JSON is missing required Desktop OAuth fields')
    return {
        'client_id': cfg['client_id'],
        'client_secret': cfg['client_secret'],
        'auth_uri': cfg.get('auth_uri', AUTH_URI),
        'token_uri': cfg.get('token_uri', TOKEN_URI),
    }


def _atomic_private_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    temp = path.with_name(f'.{path.name}.{secrets.token_hex(8)}.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        path.chmod(0o600)
    finally:
        if temp.exists():
            temp.unlink()


def _validate_scopes(scope_value: Any) -> set[str]:
    scopes = set(scope_value.split()) if isinstance(scope_value, str) else set(scope_value or [])
    expected = set(SCOPES)
    if 'https://www.googleapis.com/auth/gmail.readonly' not in scopes:
        raise ValueError('required gmail.readonly scope missing')
    if not scopes.issubset(expected):
        raise ValueError('OAuth grant contains an unexpected scope')
    return scopes


def _assert_distinct_from_send_clients(client_id: str, credential_base: pathlib.Path) -> None:
    for path in credential_base.glob('gmail-send-*/client_secret.json'):
        try:
            data = json.loads(path.read_text())
            cfg = data.get('installed') or data.get('web') or {}
        except (OSError, ValueError, TypeError):
            continue
        if cfg.get('client_id') == client_id:
            raise ValueError('read OAuth client must be separate from every Gmail-send client')


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        type(self).result = {key: values[0] for key, values in query.items() if values}
        body = b'Authorization received. You can close this tab and return to Telegram.'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def _exchange_code(client: dict[str, str], code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
    body = urllib.parse.urlencode({
        'client_id': client['client_id'],
        'client_secret': client['client_secret'],
        'code': code,
        'code_verifier': verifier,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }).encode()
    req = urllib.request.Request(
        client['token_uri'],
        data=body,
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        token = json.loads(response.read().decode())
    if not token.get('access_token') or not token.get('refresh_token'):
        raise ValueError('Google did not return both access and refresh tokens')
    return token


def _token_identity_and_scopes(access_token: str) -> tuple[str, set[str]]:
    tokeninfo_url = TOKENINFO_URI + '?' + urllib.parse.urlencode({'access_token': access_token})
    with urllib.request.urlopen(tokeninfo_url, timeout=15) as response:
        tokeninfo = json.loads(response.read().decode())
    scopes = _validate_scopes(tokeninfo.get('scope', ''))
    req = urllib.request.Request(USERINFO_URI, headers={'Authorization': f'Bearer {access_token}'})
    with urllib.request.urlopen(req, timeout=15) as response:
        userinfo = json.loads(response.read().decode())
    email = str(userinfo.get('email') or '').strip().lower()
    if not email or userinfo.get('email_verified') is not True:
        raise ValueError('Google account email is missing or unverified')
    return email, scopes


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Authorize a separate Gmail-readonly OAuth credential.')
    parser.add_argument('--account', default='sean', help='Local account label (default: sean)')
    parser.add_argument('--expected-email', required=True, help='Google account that must approve the grant')
    parser.add_argument('--client-secret', required=True, type=pathlib.Path, help='Downloaded Google Desktop OAuth JSON')
    parser.add_argument('--credential-base', type=pathlib.Path, default=pathlib.Path('~/.openclaw/credentials').expanduser())
    parser.add_argument('--replace', action='store_true', help='Replace an existing read token after explicit review')
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    label = str(args.account).strip()
    expected_email = str(args.expected_email).strip().lower()
    if not SAFE_LABEL_RE.fullmatch(label):
        raise SystemExit('Account label contains unsupported characters.')
    if '@' not in expected_email:
        raise SystemExit('Expected email is invalid.')
    source_client = args.client_secret.expanduser().resolve()
    if not source_client.is_file():
        raise SystemExit('Downloaded Desktop OAuth client JSON was not found.')

    credential_dir = args.credential_base.expanduser().resolve() / f'gmail-read-{label}'
    token_path = credential_dir / 'token.json'
    client_path = credential_dir / 'client_secret.json'
    if token_path.exists() and not args.replace:
        raise SystemExit('A read token already exists; refusing to overwrite it without --replace.')

    client = _load_client(source_client)
    _assert_distinct_from_send_clients(client['client_id'], args.credential_base.expanduser().resolve())
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip('=')
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    state = secrets.token_urlsafe(32)
    _CallbackHandler.result = {}
    server = http.server.HTTPServer(('127.0.0.1', 0), _CallbackHandler)
    server.timeout = 300
    redirect_uri = f'http://127.0.0.1:{server.server_port}/'
    auth_url = client['auth_uri'] + '?' + urllib.parse.urlencode({
        'client_id': client['client_id'],
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': ' '.join(SCOPES),
        'access_type': 'offline',
        'prompt': 'consent',
        'include_granted_scopes': 'false',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': state,
    })

    print(f'Opening Google consent for account label {label!r}.')
    print('Approve only Gmail read-only and identity access. Tokens will not be printed.')
    if not webbrowser.open(auth_url, new=1, autoraise=True):
        print('Browser launch failed. Open this URL locally:')
        print(auth_url)
    server.handle_request()
    server.server_close()
    callback = _CallbackHandler.result
    if callback.get('state') != state or not callback.get('code'):
        raise SystemExit('OAuth callback was missing or failed state validation.')

    try:
        token = _exchange_code(client, callback['code'], verifier, redirect_uri)
        email, scopes = _token_identity_and_scopes(token['access_token'])
    except Exception as exc:
        raise SystemExit(f'OAuth verification failed: {type(exc).__name__}') from None
    if email != expected_email:
        raise SystemExit('The wrong Google account approved the grant; nothing was saved.')

    saved_token = {
        'access_token': token['access_token'],
        'refresh_token': token['refresh_token'],
        'expires_at': int(time.time()) + int(token.get('expires_in', 3600)),
        'scope': ' '.join(sorted(scopes)),
        'token_type': token.get('token_type', 'Bearer'),
    }
    client_payload = json.loads(source_client.read_text())
    _atomic_private_json(client_path, client_payload)
    _atomic_private_json(token_path, saved_token)
    print(f'Gmail-readonly OAuth saved for {label!r}; account and scopes verified.')
    print(f'Credential directory: {credential_dir}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
