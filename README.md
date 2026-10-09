# Mailreef

A protective reef between hostile mail and a tool-capable agent. Mailreef is an
OpenClaw plugin that performs prose-free historical Gmail discovery and produces
bounded summaries of explicitly selected messages without exposing raw email to
the parent agent.

## Security shape

```text
Gmail readonly → Mac broker → sanitize + deterministic tripwires → zero-tool Luna summary
               → deterministic schema/evidence gate → fresh Luna relay gate
               → explicitly untrusted envelope
```

The output cannot authorize sends, commands, purchases, credential changes, URL
fetches, or any other action. The plugin emits no raw URL, accepts only evidence
quoted from the screened source, and fails closed on detector/model/schema errors.

Every source or safety-contract change requires the separate activation checklist
before that version may be described as live.

## Components

- `mailreef_broker.py` — Mac-local Gmail fetch, normalization, pre-screen,
  scope enforcement, and append-only audit.
- `scripts/bootstrap_mailreef_oauth.py` — local PKCE OAuth bootstrap that
  requests only Gmail read-only plus identity scopes and never prints tokens.
- `scripts/activation_preflight.py` — offline, secret-safe verification of the
  broker pin, account boundary, OAuth files/scopes, and host model policy.
- `mailreef-plugin/` — native node invocation plus isolated OpenClaw
  model completions and the post-summary gate.
- `tests/` — offline Python security tests.
- `docs/` — architecture and activation requirements.

## Offline verification

```bash
python3 -m unittest discover -s tests -v
cd mailreef-plugin && npm run check
```

No test reads Gmail, OAuth material, or live email content.

## OAuth bootstrap

Create a separate Google Desktop OAuth client for the read lane, download its
JSON locally, then run:

```bash
python3 scripts/bootstrap_mailreef_oauth.py \
  --account sean \
  --expected-email you@example.com \
  --client-secret /path/to/downloaded-client.json
```

The script opens Google consent locally, verifies the approving identity and
exact scope set, and stores private files under
`~/.openclaw/credentials/mailreef-sean/`. It refuses to overwrite an existing
token unless `--replace` is explicitly supplied. After success, move the
original downloaded client JSON to Trash so the private credential directory is
the only retained copy.

## Limits

- Gmail read-only only; no send/modify/label/delete capabilities.
- Recent triage remains capped at 5 messages / 7 days per operation.
- Historical discovery accepts structured date plus sender/subject filters,
  returns at most 10 message IDs and Gmail internal timestamps, and makes zero
  model calls. It exposes no sender, subject, snippet, or body prose.
- One search window may span at most 366 days and may reach back 10 years.
  Windows over 31 days require a sender or subject filter. Discovery is
  inbox-only, excludes spam/trash, and intentionally has no pagination.
- A selected message ID may then be read through the existing two-stage safety
  pipeline.
- Attachments and nested messages are excluded from body extraction.
- The plugin ships with `activation.onStartup: false`; deployment and runtime
  activation remain separate operator-controlled steps.

See [Architecture](docs/ARCHITECTURE.md) and [Activation](docs/ACTIVATION.md).
The exact Google-side setup is in [Google Cloud OAuth Handoff](docs/GCP-OAUTH-HANDOFF.md).
