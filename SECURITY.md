# Security Policy

Do not submit real email content, OAuth tokens, credential files, audit logs, or
personal addresses in issues or test fixtures. Use synthetic messages only.

Treat bypasses that expose email-derived prose to a tool-capable agent, allow a
caller-controlled executable/path, weaken fail-closed behavior, or broaden Gmail
scope as security vulnerabilities.

The injection gate is intentionally not a generic phishing or action-risk filter.
Human-facing calls to action remain summarizable inside the non-authorizing
envelope. Prompt injection means source content that targets an AI/assistant/
agent/model, its instructions or policy, its tools or secrets, or hidden/encoded
execution. The independent post-gate also blocks a summary that relays source
content as an instruction to the receiving agent. Human-facing OTP, MFA,
verification, password, and other credential content is not prompt injection by
itself and may pass only when evidence-backed; agent-directed attempts to obtain
or reveal secrets remain blocked.

This project is experimental and disabled by default. A passing offline suite is
not proof that a live account or runtime has been safely configured.
