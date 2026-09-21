#!/usr/bin/env python3
"""Mac-side Gmail READ broker.

Runs on the MacBook. Fetches Gmail via local-only OAuth tokens, sanitizes
content, applies deterministic prompt-injection tripwires, and returns a safe
JSON envelope. No remote host receives Gmail tokens.

Intended to be called locally by the OpenClaw plugin or through its explicit
Mac-node route. The CLI returns only a screened JSON envelope.

Default behaviour:
  - Reads from Mac-local credential path (Keychain-backed or file-based).
  - Inbox only, unread only, last 7 days, max 5 messages.
  - No attachments.
  - Deterministic prescreen only; isolated Luna stages run in the plugin.
  - No prescreen bypass or emergency-model path exists.
  - Fails closed if prescreening or the audit log is unavailable.
  - Returns JSON with safe metadata/body, prescreen verdict, and audit fields.
  - Never returns raw MIME/HTML.
"""
from __future__ import annotations

import argparse
import base64
import datetime
import html
import json
import os
import pathlib
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GMAIL_API_BASE = 'https://gmail.googleapis.com/gmail/v1/users/me'
TOKENINFO_URL = 'https://www.googleapis.com/oauth2/v1/tokeninfo'

DEFAULT_MAX_LIST = 5
DEFAULT_DAYS_BACK = 7

# Mac-local credential base path
MAC_CREDENTIAL_BASE = pathlib.Path(
    os.environ.get(
        'MAC_GMAIL_READ_CREDENTIAL_BASE',
        os.path.expanduser('~/.openclaw/credentials'),
    )
)

# Broker audit log on Mac
MAC_BROKER_AUDIT_LOG = pathlib.Path(
    os.environ.get(
        'MAC_BROKER_AUDIT_LOG',
        os.path.expanduser('~/.openclaw/broker-audit.log'),
    )
)

# Scopes: read-only
SCOPES = (
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
)

FORBIDDEN_SCOPE_FRAGMENTS = (
    'gmail.send', 'gmail.modify', 'gmail.compose',
    'gmail.insert', 'gmail.labels', 'gmail.settings',
    'mail.google.com',
)


# ---------------------------------------------------------------------------
# Audit logging (Mac-side, JSON-lines, no secrets)
# ---------------------------------------------------------------------------

def broker_audit_log(entry: dict[str, Any]) -> None:
    """Append one durable JSON record. Audit failure is a security failure."""
    record = {
        'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'source': 'mac_email_read_broker',
        **entry,
    }
    for k in ('access_token', 'refresh_token', 'client_secret',
              'token', 'body', 'body_text', 'raw_body',
              'body_html', 'body_plain'):
        record.pop(k, None)
    MAC_BROKER_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    fd = os.open(MAC_BROKER_AUDIT_LOG, flags, 0o600)
    try:
        payload = (json.dumps(record, default=str, separators=(',', ':')) + '\n').encode()
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Sanitizer (inline, no dependency on VPS paths)
# ---------------------------------------------------------------------------

def sanitize_email_content(raw_content: str) -> str:
    """Decode, normalize, and strip active/hidden content deterministically."""
    if not raw_content:
        return ''
    content = raw_content
    for _ in range(3):
        decoded = html.unescape(content)
        if decoded == content:
            break
        content = decoded
    content = unicodedata.normalize('NFKC', content)
    content = ''.join(
        ch for ch in content
        if unicodedata.category(ch) not in ('Cf', 'Cs', 'Co')
        and (unicodedata.category(ch) != 'Cc' or ch in ('\n', '\t'))
    )
    content = re.sub(r'<script\b[^>]*>.*?(?:</script>|$)', '', content,
                     flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'<style\b[^>]*>.*?(?:</style>|$)', '', content,
                     flags=re.DOTALL | re.IGNORECASE)
    content = re.sub(r'<!--.*?(?:-->|$)', '', content, flags=re.DOTALL)
    content = re.sub(
        r'<(?:object|embed|iframe|form|input|button|select|textarea)\b[^>]*>'
        r'.*?(?:</(?:object|embed|iframe|form|input|button|select|textarea)>|$)',
        '', content, flags=re.DOTALL | re.IGNORECASE,
    )
    content = re.sub(r'<[^>]*>', ' ', content)
    return re.sub(r'\s+', ' ', content).strip()


# ---------------------------------------------------------------------------
# Deterministic injection tripwires (Mac-local)
# ---------------------------------------------------------------------------

_HEURISTIC_PATTERNS = [
    (r'(?i)ignore\s+(all\s+)?previous\s+instructions', 'instruction override'),
    (r'(?i)disregard\s+(all\s+)?(previous|above)', 'instruction override'),
    (r'(?i)forget\s+everything', 'memory reset'),
    (r'(?i)you\s+are\s+now\s+(dan|developer|system|admin)', 'role-change'),
    (r'(?i)system\s*:', 'system-role impersonation'),
    (r'(?i)override\s+(security|safety|policy|instructions)', 'security override'),
    (r'(?i)(reveal|show|print|return|send|upload|exfiltrat\w*)\b.{0,80}\b(secret|credential|token|password|private key|environment variable)', 'secret request'),
    (r'(?i)(call|invoke|run|execute|use)\b.{0,60}\b(tool|command|shell|terminal|browser|api)', 'tool request'),
    (r'(?i)(assistant|agent|model)\s*[:,]\s*(must|should|ignore|follow|execute|respond)', 'agent-directed instruction'),
    (r'(?i)(developer|system|assistant)\s+(message|instruction|prompt)', 'control-message reference'),
    (r'(?i)(do not|never)\s+(mention|disclose|tell|show).{0,60}(instruction|prompt|request)', 'concealment request'),
    (r'(?i)(decode|decrypt|deobfuscate)\b.{0,60}\b(payload|instruction|message)', 'encoded instruction request'),
]

MAX_PRESCREEN_CHARS = 24_000


def _heuristic_check(text: str) -> tuple[bool, str, float]:
    for pattern, reason in _HEURISTIC_PATTERNS:
        if re.search(pattern, text):
            return True, f'Heuristic: {reason}', 0.90
    # base64 payloads
    for m in re.finditer(r'(?i)(?:base64\s*:\s*)?([A-Za-z0-9+/]{24,}={0,2})', text):
        try:
            decoded = base64.b64decode(m.group(1) + '===', validate=False).decode('utf-8', 'replace')
        except Exception:
            continue
        for pattern, reason in _HEURISTIC_PATTERNS:
            if re.search(pattern, decoded):
                return True, f'Heuristic (base64): {reason}', 0.85
    return False, '', 0.0


def detect_injection(text: str) -> tuple[bool, str, float]:
    """Apply deterministic tripwires over the complete bounded text."""
    if len(text) > MAX_PRESCREEN_CHARS:
        raise ValueError('content exceeds prescreen budget')
    hit, reason, conf = _heuristic_check(text)
    if hit:
        return hit, reason, conf
    if not text:
        return False, 'empty', 1.0
    return False, 'no deterministic tripwire matched', 1.0


# ---------------------------------------------------------------------------
# Credential helpers (Mac-local only, never prints contents)
# ---------------------------------------------------------------------------

def _load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _load_accounts_config(config_path: pathlib.Path | None = None) -> list[dict[str, Any]]:
    """Load accounts from Mac-local config."""
    if config_path is None:
        config_path = MAC_CREDENTIAL_BASE / 'gmail-read-accounts.json'
    data = _load_json(config_path)
    return data.get('accounts', [])


def _get_account(accounts: list[dict[str, Any]], label: str) -> dict[str, Any]:
    for acct in accounts:
        if acct.get('label') == label:
            return acct
    raise SystemExit(f'BROKER-ERROR: account {label!r} not found in config')


def _get_access_token(account: dict[str, Any]) -> str:
    """Load and optionally refresh the access token. Mac-local only."""
    cred_dir = pathlib.Path(account['credential_dir'])
    token_path = cred_dir / 'token.json'
    client_secret_path = cred_dir / 'client_secret.json'

    if not token_path.is_file():
        raise SystemExit(
            f'BROKER-ERROR: no token.json at {token_path}. '
            f'Run OAuth flow for account {account["label"]!r} on this Mac.'
        )

    token = _load_json(token_path)
    access_token = token.get('access_token', '')
    expires_at = token.get('expires_at')

    # Check if token needs refresh
    needs_refresh = False
    if isinstance(expires_at, (int, float)):
        needs_refresh = time.time() >= float(expires_at) - 120
    elif not access_token:
        needs_refresh = True

    if needs_refresh:
        refresh_token = token.get('refresh_token')
        if not refresh_token:
            if access_token:
                return access_token
            raise SystemExit(
                f'BROKER-ERROR: token expired and no refresh_token for {account["label"]!r}'
            )
        if not client_secret_path.is_file():
            raise SystemExit(
                f'BROKER-ERROR: need client_secret.json at {client_secret_path} to refresh token'
            )
        cs = _load_json(client_secret_path)
        cfg = cs.get('installed') or cs.get('web') or {}
        body = urllib.parse.urlencode({
            'client_id': cfg['client_id'],
            'client_secret': cfg['client_secret'],
            'refresh_token': refresh_token,
            'grant_type': 'refresh_token',
        }).encode()
        req = urllib.request.Request(
            cfg.get('token_uri', 'https://oauth2.googleapis.com/token'),
            data=body,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            refreshed = json.loads(resp.read().decode())
        merged = {**token, **refreshed, 'refresh_token': refresh_token}
        if 'expires_in' in refreshed:
            merged['expires_at'] = int(time.time()) + int(refreshed['expires_in'])
        token_path.write_text(json.dumps(merged, indent=2, sort_keys=True))
        token_path.chmod(0o600)
        return merged['access_token']

    return access_token


def validate_token_scopes(access_token: str) -> None:
    """Require read-only Gmail scope and reject broader Gmail authority."""
    url = TOKENINFO_URL + '?' + urllib.parse.urlencode({'access_token': access_token})
    with urllib.request.urlopen(url, timeout=15) as resp:
        token_info = json.loads(resp.read().decode())
    scope_value = token_info.get('scope', '')
    scopes = set(scope_value.split()) if isinstance(scope_value, str) else set(scope_value or [])
    if 'https://www.googleapis.com/auth/gmail.readonly' not in scopes:
        raise PermissionError('required gmail.readonly scope missing')
    if not scopes.issubset(set(SCOPES)):
        raise PermissionError('unexpected OAuth scope present')
    if any(fragment in scope for scope in scopes for fragment in FORBIDDEN_SCOPE_FRAGMENTS):
        raise PermissionError('forbidden Gmail scope present')


# ---------------------------------------------------------------------------
# Gmail API helpers (read-only, Mac-side)
# ---------------------------------------------------------------------------

def _gmail_get(access_token: str, endpoint: str, params: Any | None = None) -> dict[str, Any]:
    url = f'{GMAIL_API_BASE}/{endpoint}'
    if params:
        url += '?' + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {access_token}'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _list_messages(
    access_token: str,
    *,
    max_results: int = DEFAULT_MAX_LIST,
    days_back: int = DEFAULT_DAYS_BACK,
) -> list[dict[str, Any]]:
    after_date = (datetime.date.today() - datetime.timedelta(days=days_back)).strftime('%Y/%m/%d')
    query = f'after:{after_date}'
    params = {'maxResults': str(max_results), 'q': query}
    label_params = '&'.join(f'labelIds={lid}' for lid in ('INBOX', 'UNREAD'))
    url = f'{GMAIL_API_BASE}/messages?{urllib.parse.urlencode(params)}&{label_params}'
    req = urllib.request.Request(url, headers={'Authorization': f'Bearer {access_token}'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    return data.get('messages', [])


def _get_message_metadata(access_token: str, message_id: str) -> dict[str, Any]:
    return _gmail_get(access_token, f'messages/{message_id}', {
        'format': 'metadata',
        'metadataHeaders': ['From', 'To', 'Subject', 'Date'],
    })


def _get_message_full(access_token: str, message_id: str) -> dict[str, Any]:
    return _gmail_get(access_token, f'messages/{message_id}', {'format': 'full'})


def _extract_header(msg: dict[str, Any], name: str) -> str:
    for h in msg.get('payload', {}).get('headers', []):
        if h.get('name', '').lower() == name.lower():
            return h.get('value', '')
    return ''


def _extract_body_text(msg: dict[str, Any]) -> str:
    payload = msg.get('payload', {})

    def _decode(data: str) -> str:
        if not data:
            return ''
        padded = data + '=' * (4 - len(data) % 4)
        try:
            return base64.urlsafe_b64decode(padded).decode('utf-8', errors='replace')
        except Exception:
            return ''

    def _walk(part: dict) -> tuple[str, str]:
        mime = part.get('mimeType', '')
        headers = {
            str(header.get('name', '')).lower(): str(header.get('value', ''))
            for header in part.get('headers', [])
        }
        disposition = headers.get('content-disposition', '').lower()
        if 'attachment' in disposition or mime == 'message/rfc822':
            return '', ''
        body_data = part.get('body', {}).get('data', '')
        plain = html_text = ''
        if mime == 'text/plain' and body_data:
            plain = _decode(body_data)
        elif mime == 'text/html' and body_data:
            html_text = _decode(body_data)
        for sub in part.get('parts', []):
            sp, sh = _walk(sub)
            plain = plain or sp
            html_text = html_text or sh
        return plain, html_text

    plain, html_text = _walk(payload)
    return plain if plain else html_text


# ---------------------------------------------------------------------------
# Prescreening pipeline
# ---------------------------------------------------------------------------

def prescreen(
    text: str,
    *,
    context: str,
) -> dict[str, Any]:
    """Sanitize and injection-check text. Returns screening result dict."""
    sanitized = sanitize_email_content(text)

    try:
        is_injection, reason, confidence = detect_injection(sanitized)
    except Exception:
        broker_audit_log({
            'action': 'prescreen_detector_error',
            'context': context,
            'reason_code': 'detector_unavailable_or_malformed',
        })
        return {
            'sanitized_text': None,
            'detector_ran': False,
            'verdict': 'ERROR',
            'reason_code': 'detector_unavailable_or_malformed',
            'confidence': 0.0,
        }

    verdict = 'INJECTION' if is_injection else 'SAFE'
    if is_injection:
        broker_audit_log({
            'action': 'prescreen_injection_detected',
            'context': context,
            'reason_code': 'injection_detected',
            'confidence': confidence,
        })

    return {
        'sanitized_text': sanitized if not is_injection else None,
        'detector_ran': True,
        'verdict': verdict,
        'reason_code': 'injection_detected' if is_injection else 'none',
        'confidence': confidence,
    }


def screen_fields(
    fields: dict[str, str],
    *,
    context_id: str,
) -> dict[str, Any]:
    """Screen every human-authored output surface and expose only SAFE text."""
    result: dict[str, Any] = {}
    for name, value in fields.items():
        screened = prescreen(
            value,
            context=f'{name}:{context_id}',
        )
        result[name] = screened['sanitized_text'] if screened['verdict'] == 'SAFE' else None
        result[f'{name}_verdict'] = screened['verdict']
        if screened['verdict'] != 'SAFE':
            result[f'{name}_reason_code'] = screened['reason_code']
    field_verdicts = [result[f'{name}_verdict'] for name in fields]
    if all(verdict == 'SAFE' for verdict in field_verdicts):
        aggregate = prescreen(
            '\n'.join(str(result[name] or '') for name in fields),
            context=f'aggregate:{context_id}',
        )
        result['aggregate_verdict'] = aggregate['verdict']
        if aggregate['verdict'] != 'SAFE':
            result['aggregate_reason_code'] = aggregate['reason_code']
    else:
        result['aggregate_verdict'] = 'BLOCKED'
        result['aggregate_reason_code'] = 'unsafe_component'
    return result


# ---------------------------------------------------------------------------
# Broker operations
# ---------------------------------------------------------------------------

def broker_list(
    account_label: str,
    *,
    max_results: int = DEFAULT_MAX_LIST,
    days_back: int = DEFAULT_DAYS_BACK,
    config_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    """List inbox messages, sanitize+screen, return safe JSON envelope."""
    if not 1 <= max_results <= DEFAULT_MAX_LIST or not 1 <= days_back <= DEFAULT_DAYS_BACK:
        return _error_envelope(account_label, 'requested scope exceeds broker limits')
    accounts = _load_accounts_config(config_path)
    account = _get_account(accounts, account_label)

    if account.get('can_read') is not True:
        return _error_envelope(account_label, 'can_read is false for this account')

    access_token = _get_access_token(account)
    validate_token_scopes(access_token)
    messages = _list_messages(access_token, max_results=max_results, days_back=days_back)

    if not messages:
        broker_audit_log({
            'action': 'broker_list',
            'account': account_label,
            'result_count': 0,
        })
        return _success_envelope(account_label, 'list', [])

    results = []
    for stub in messages:
        meta = _get_message_metadata(access_token, stub['id'])
        screened = screen_fields({
            'from': _extract_header(meta, 'From'),
            'date': _extract_header(meta, 'Date'),
            'subject': _extract_header(meta, 'Subject'),
            'snippet': meta.get('snippet', ''),
        }, context_id=stub['id'])
        entry: dict[str, Any] = {
            'id': stub['id'],
            'threadId': stub.get('threadId', ''),
            **screened,
        }
        results.append(entry)

    broker_audit_log({
        'action': 'broker_list',
        'account': account_label,
        'result_count': len(results),
        'message_ids': [r['id'] for r in results],
    })

    return _success_envelope(account_label, 'list', results)


def broker_read(
    account_label: str,
    message_id: str,
    *,
    read_body: bool = False,
    config_path: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Read a specific message, sanitize+screen, return safe JSON envelope."""
    accounts = _load_accounts_config(config_path)
    account = _get_account(accounts, account_label)

    if account.get('can_read') is not True:
        return _error_envelope(account_label, 'can_read is false for this account')

    access_token = _get_access_token(account)
    validate_token_scopes(access_token)

    if read_body:
        full = _get_message_full(access_token, message_id)
        screened = screen_fields({
            'from': _extract_header(full, 'From'),
            'to': _extract_header(full, 'To'),
            'date': _extract_header(full, 'Date'),
            'subject': _extract_header(full, 'Subject'),
            'body': _extract_body_text(full),
        }, context_id=message_id)
        result: dict[str, Any] = {'id': message_id, **screened}
        broker_audit_log({
            'action': 'broker_read_body',
            'account': account_label,
            'message_id': message_id,
            'body_verdict': screened['body_verdict'],
        })
        return _success_envelope(account_label, 'read', result)

    meta = _get_message_metadata(access_token, message_id)
    screened = screen_fields({
        'from': _extract_header(meta, 'From'),
        'to': _extract_header(meta, 'To'),
        'date': _extract_header(meta, 'Date'),
        'subject': _extract_header(meta, 'Subject'),
        'snippet': meta.get('snippet', ''),
    }, context_id=message_id)
    result = {'id': message_id, **screened}
    broker_audit_log({
        'action': 'broker_read_metadata',
        'account': account_label,
        'message_id': message_id,
    })
    return _success_envelope(account_label, 'read', result)


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

def _success_envelope(account: str, operation: str, data: Any) -> dict[str, Any]:
    return {
        'status': 'ok',
        'broker': 'mac_email_read_broker',
        'broker_version': '1.2.0',
        'account': account,
        'operation': operation,
        'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'data': data,
    }


def _error_envelope(account: str, error: str) -> dict[str, Any]:
    return {
        'status': 'error',
        'broker': 'mac_email_read_broker',
        'broker_version': '1.2.0',
        'account': account,
        'ts': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'error': error,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description='Mac-side Gmail READ broker. Returns safe JSON to stdout.',
    )
    p.add_argument('--account', required=True, help='Account label')

    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--list', action='store_true', help='List inbox messages')
    mode.add_argument('--message-id', help='Fetch specific message')

    p.add_argument('--max', type=int, default=DEFAULT_MAX_LIST)
    p.add_argument('--days', type=int, default=DEFAULT_DAYS_BACK)
    p.add_argument('--read-body', action='store_true')
    p.add_argument('--config', type=pathlib.Path, default=None,
                   help='Path to gmail-read-accounts.json')
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])

    config_path = args.config

    if args.list:
        result = broker_list(
            args.account,
            max_results=args.max,
            days_back=args.days,
            config_path=config_path,
        )
    elif args.message_id:
        result = broker_read(
            args.account,
            args.message_id,
            read_body=args.read_body,
            config_path=config_path,
        )
    else:
        return 1

    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result.get('status') == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())
