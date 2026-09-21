# Screened Gmail Read Plugin

OpenClaw plugin layer for the disabled-by-default screened Gmail project.

It registers:

- owner-only tool `gmail_read_screened`
- authenticated command `/gmailread`
- dangerous node-host command `screened-gmail-read.broker`
- a validating node-invoke policy

The broker path, Python executable, node target, and timeout are operator config;
caller input cannot override them. Successful broker output is transformed by a
native zero-tool Luna completion, strict deterministic validation, and a
fresh zero-tool Luna relay detector. Raw source and blocked candidates are not
returned in tool details.

Defaults:

- account: `sean`
- maximum scope: 5 messages / 7 days
- summarizer: `openai/gpt-5.6-luna`
- post-detector: `openai/gpt-5.6-luna`
- broker: `/Users/Sean/projects/openclaw-gmail-read/mac_email_read_broker.py`

Verification:

```bash
npm run check
```

This does not activate the plugin or access Gmail. Follow the repository's
`docs/ACTIVATION.md` only after explicit operator approval.
