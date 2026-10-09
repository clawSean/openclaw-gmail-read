# Mailreef Plugin

OpenClaw plugin layer for Mailreef's prose-free Gmail discovery and screened
message reader.

It registers:

- owner-only tool `mailreef_read`
- authenticated command `/mailreef`
- dangerous node-host command `mailreef.broker`
- a validating node-invoke policy

The broker path, Python executable, node target, and timeout are operator config;
caller input cannot override them. Successful broker output is transformed by a
native zero-tool Luna completion, strict deterministic validation, and a
fresh zero-tool Luna relay detector. Raw source and blocked candidates are not
returned in tool details.

The detector targets agent-directed prompt injection and summary relay, not
ordinary requests to the human recipient. Human CTAs are returned only in the
descriptive `The email asks the reader to ...` frame, and every envelope remains
unable to authorize action.

The broker uses deterministic local tripwires and has no Ollama or local-model
runtime dependency.

Defaults:

- account: `sean`
- recent scope: 5 messages / 7 days
- historical discovery: 10 IDs/timestamps, 366-day window, 10-year age floor,
  sender/subject selector, inbox-only, no pagination
- summarizer: `openai/gpt-5.6-luna`
- post-detector: `openai/gpt-5.6-luna`
- broker: `/Users/Sean/projects/mailreef/mailreef_broker.py`

Verification:

```bash
npm run check
```

This check does not activate the plugin or access Gmail. Follow the repository's
`docs/ACTIVATION.md` after explicit operator approval for deployment/runtime
changes.
