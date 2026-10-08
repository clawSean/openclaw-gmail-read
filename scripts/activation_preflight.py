#!/usr/bin/env python3
"""Offline, secret-safe activation preflight for Mailreef."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any


MODEL = 'openai/gpt-5.6-luna'
SCOPES = {
    'https://www.googleapis.com/auth/gmail.readonly',
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
}


class Check:
    def __init__(self, name: str, ok: bool, detail: str) -> None:
        self.name = name
        self.ok = ok
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {'name': self.name, 'ok': self.ok, 'detail': self.detail}


def _json(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError('expected a JSON object')
    return value


def _mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check_file(checks: list[Check], name: str, path: pathlib.Path, mode: int) -> bool:
    ok = path.is_file() and not path.is_symlink() and _mode(path) == mode
    checks.append(Check(name, ok, 'present with private mode' if ok else f'missing, symlinked, or not mode {mode:04o}'))
    return ok


def run_checks(args: argparse.Namespace) -> dict[str, Any]:
    root = args.project_root.expanduser().resolve()
    credential_base = args.credential_base.expanduser().resolve()
    account = args.account
    credential_dir = credential_base / f'mailreef-{account}'
    broker = root / 'mailreef_broker.py'
    plugin_source = root / 'mailreef-plugin' / 'src' / 'index.js'
    accounts_path = credential_base / 'mailreef-accounts.json'
    checks: list[Check] = []

    checks.append(Check('canonical project files', broker.is_file() and plugin_source.is_file(), 'broker and plugin source found'))
    if broker.is_file() and plugin_source.is_file():
        match = re.search(r'EXPECTED_BROKER_SHA256\s*=\s*"([0-9a-f]{64})"', plugin_source.read_text())
        actual = _sha256(broker)
        checks.append(Check('broker hash pin', bool(match) and match.group(1) == actual, 'plugin pin matches canonical broker' if match and match.group(1) == actual else 'plugin pin does not match canonical broker'))

    config_ok = args.openclaw_config.is_file()
    checks.append(Check('OpenClaw config readable', config_ok, 'config file found' if config_ok else 'config file missing'))
    if config_ok:
        try:
            oc = _json(args.openclaw_config)
            entry = oc.get('plugins', {}).get('entries', {}).get('mailreef', {})
            cfg = entry.get('config', {})
            llm = entry.get('llm', {})
            expected_enabled = args.phase == 'live'
            checks.extend([
                Check('plugin activation phase', entry.get('enabled') is expected_enabled, f'expected enabled={str(expected_enabled).lower()}'),
                Check('default account pinned', cfg.get('defaultAccount') == account, f'expected account {account!r}'),
                Check('broker path canonical', pathlib.Path(str(cfg.get('macBrokerScriptPath', ''))).expanduser().resolve() == broker, 'configured path matches canonical broker'),
                Check('plugin models pinned', cfg.get('summarizerModel') == MODEL and cfg.get('postDetectorModel') == MODEL, f'both stages must use {MODEL}'),
                Check('model override explicitly trusted', llm.get('allowModelOverride') is True, 'host trust must be explicit'),
                Check('model override allowlist exact', set(llm.get('allowedModels') or []) == {MODEL}, 'allowedModels must contain only Luna'),
                Check('completion allowlist exact', set(llm.get('allowedCompletionModels') or []) == {MODEL}, 'allowedCompletionModels must contain only Luna'),
            ])
        except (OSError, ValueError, TypeError) as exc:
            checks.append(Check('OpenClaw config structure', False, f'invalid config structure: {type(exc).__name__}'))

    registry_ok = accounts_path.is_file() and not accounts_path.is_symlink() and _mode(accounts_path) == 0o600
    checks.append(Check('account registry private', registry_ok, 'registry found with mode 0600' if registry_ok else 'registry missing, symlinked, or not mode 0600'))
    if registry_ok:
        try:
            accounts = _json(accounts_path).get('accounts', [])
            row = next((item for item in accounts if item.get('label') == account), None)
            expected_can_read = args.phase == 'live'
            checks.extend([
                Check('account registry row', isinstance(row, dict), f'account {account!r} is registered'),
                Check('credential directory pinned', isinstance(row, dict) and pathlib.Path(str(row.get('credential_dir', ''))).expanduser().resolve() == credential_dir, 'registry points only to dedicated read directory'),
                Check('account activation phase', isinstance(row, dict) and row.get('can_read') is expected_can_read, f'expected can_read={str(expected_can_read).lower()}'),
            ])
        except (OSError, ValueError, TypeError) as exc:
            checks.append(Check('account registry structure', False, f'invalid registry: {type(exc).__name__}'))

    dir_ok = credential_dir.is_dir() and not credential_dir.is_symlink() and _mode(credential_dir) == 0o700
    checks.append(Check('credential directory private', dir_ok, 'dedicated directory is mode 0700' if dir_ok else 'directory missing, symlinked, or not mode 0700'))
    client_path = credential_dir / 'client_secret.json'
    token_path = credential_dir / 'token.json'
    client_ok = _check_file(checks, 'Desktop OAuth client private', client_path, 0o600) if dir_ok else False
    token_ok = _check_file(checks, 'OAuth token private', token_path, 0o600) if dir_ok else False

    read_client_id = ''
    if client_ok:
        try:
            installed = _json(client_path).get('installed', {})
            read_client_id = str(installed.get('client_id') or '')
            checks.append(Check('Desktop OAuth client shape', bool(read_client_id and installed.get('client_secret')), 'installed-app client fields present'))
        except (OSError, ValueError, TypeError) as exc:
            checks.append(Check('Desktop OAuth client shape', False, f'invalid client JSON: {type(exc).__name__}'))
    if read_client_id:
        reused = False
        for send_path in credential_base.glob('gmail-send-*/client_secret.json'):
            try:
                send = _json(send_path)
                cfg = send.get('installed') or send.get('web') or {}
                reused = reused or cfg.get('client_id') == read_client_id
            except (OSError, ValueError, TypeError):
                continue
        checks.append(Check('read client distinct from send clients', not reused, 'no Gmail-send client reuses this client id'))

    if token_ok:
        try:
            token = _json(token_path)
            scopes = set(str(token.get('scope') or '').split())
            checks.extend([
                Check('OAuth scopes exact', scopes == SCOPES, 'grant is Gmail readonly plus identity only'),
                Check('refresh token present', bool(token.get('refresh_token')), 'offline refresh credential present'),
            ])
        except (OSError, ValueError, TypeError) as exc:
            checks.append(Check('OAuth token shape', False, f'invalid token JSON: {type(exc).__name__}'))

    ready = bool(checks) and all(item.ok for item in checks)
    return {
        'schemaVersion': '1',
        'phase': args.phase,
        'account': account,
        'status': 'ready' if ready else 'blocked',
        'checks': [item.to_dict() for item in checks],
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Offline activation preflight; prints no credential values.')
    parser.add_argument('--phase', choices=('prepare', 'live'), default='prepare')
    parser.add_argument('--account', default='sean')
    parser.add_argument('--project-root', type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[1])
    parser.add_argument('--credential-base', type=pathlib.Path, default=pathlib.Path('~/.openclaw/credentials').expanduser())
    parser.add_argument('--openclaw-config', type=pathlib.Path, default=pathlib.Path('~/.openclaw/openclaw.json').expanduser())
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    result = run_checks(parse_args(argv if argv is not None else sys.argv[1:]))
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'ready' else 1


if __name__ == '__main__':
    raise SystemExit(main())
