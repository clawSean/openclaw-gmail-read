# Screened Gmail Read for OpenClaw

An experimental, disabled-by-default OpenClaw plugin for producing bounded Gmail
summaries without exposing raw email to a tool-capable parent agent.

## Security shape

```text
Gmail readonly → Mac broker → sanitize + deterministic tripwires → zero-tool Luna summary
               → deterministic schema/evidence gate → fresh Luna relay gate
               → explicitly untrusted envelope
```

The output cannot authorize sends, commands, purchases, credential changes, URL
fetches, or any other action. The plugin emits no raw URL, accepts only evidence
quoted from the screened source, and fails closed on detector/model/schema errors.

This remains disabled until the separate activation checklist is completed.

## Components

- `mac_email_read_broker.py` — Mac-local Gmail fetch, normalization, pre-screen,
  scope enforcement, and append-only audit.
- `scripts/bootstrap_gmail_read_oauth.py` — local PKCE OAuth bootstrap that
  requests only Gmail read-only plus identity scopes and never prints tokens.
- `openclaw-email-read-plugin/` — native node invocation plus isolated OpenClaw
  model completions and the post-summary gate.
- `tests/` — offline Python security tests.
- `docs/` — architecture and activation requirements.

## Offline verification

```bash
python3 -m unittest discover -s tests -v
cd openclaw-email-read-plugin && npm run check
```

No test reads Gmail, OAuth material, or live email content.

## OAuth bootstrap

Create a separate Google Desktop OAuth client for the read lane, download its
JSON locally, then run:

```bash
python3 scripts/bootstrap_gmail_read_oauth.py \
  --account sean \
  --expected-email you@example.com \
  --client-secret /path/to/downloaded-client.json
```

The script opens Google consent locally, verifies the approving identity and
exact scope set, and stores private files under
`~/.openclaw/credentials/gmail-read-sean/`. It refuses to overwrite an existing
token unless `--replace` is explicitly supplied. After success, move the
original downloaded client JSON to Trash so the private credential directory is
the only retained copy.

## Limits

- Gmail read-only only; no send/modify/label/delete capabilities.
- Maximum 5 messages and 7 days per operation.
- Attachments and nested messages are excluded from body extraction.
- The plugin ships with `activation.onStartup: false` and must remain disabled
  until the live rollout gate passes.

See [Architecture](docs/ARCHITECTURE.md) and [Activation](docs/ACTIVATION.md).
