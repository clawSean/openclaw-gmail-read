# Screened Gmail Read for OpenClaw

An experimental, disabled-by-default OpenClaw plugin for producing bounded Gmail
summaries without exposing raw email to a tool-capable parent agent.

## Security shape

```text
Gmail readonly → Mac broker → sanitize + pre-screen → zero-tool Luna summary
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

## Limits

- Gmail read-only only; no send/modify/label/delete capabilities.
- Maximum 5 messages and 7 days per operation.
- Attachments and nested messages are excluded from body extraction.
- The plugin ships with `activation.onStartup: false` and must remain disabled
  until the live rollout gate passes.

See [Architecture](docs/ARCHITECTURE.md) and [Activation](docs/ACTIVATION.md).
