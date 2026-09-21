# Baseline Plugin Audit

Date: 2026-09-21

## Identity and source

- Plugin id: `screened-gmail-read`
- Version: `0.4.0`
- Canonical source: `openclaw-email-read-plugin/`
- Runtime discovery source resolves to this project tree.
- Dependencies: none.

## Security shape

- Pinned Mac-local broker with narrow Gmail readonly scope.
- Local deterministic sanitization and prompt-injection prescreen.
- Two fresh zero-tool `openai/gpt-5.6-luna` calls with separate prompts and no
  shared context.
- Deterministic schema, evidence, URL, and descriptive-request validation sits
  between the calls.
- Every result is explicitly untrusted and cannot authorize actions.
- Malformed output, detector outage, audit failure, and non-`SAFE` verdicts
  fail closed.

## Proof

- `python3 -m unittest discover -s tests -v`: 18/18 passed.
- `npm --prefix openclaw-email-read-plugin run check`: passed.
- `openclaw config validate --json`: valid; expected disabled-plugin warning.
- `openclaw plugins inspect screened-gmail-read --json`: canonical source
  discovered; plugin disabled.

## Missing live proof

- Gmail-read account entries remain `can_read: false`, retain stale Linux
  credential paths, and have no read OAuth token on this Mac.
- No plugin activation, Gateway restart, Gmail read, or real-email canary was
  performed.
