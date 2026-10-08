# Baseline Plugin Audit

Date: 2026-10-08

## Identity and source

- Plugin id: `screened-gmail-read`
- Version: `0.5.0`
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

- `python3 -m unittest discover -s tests -v`: 25/25 passed.
- `npm --prefix openclaw-email-read-plugin run check`: passed.
- Email skill baseline: 9/9 passed.
- Python compilation and `git diff --check`: passed.
- Offline activation preflight correctly reports the remaining host-config and
  OAuth blockers without exposing credential values.
- `openclaw config validate --json`: valid; expected disabled-plugin warning.
- `openclaw plugins inspect screened-gmail-read --json`: canonical source
  discovered; plugin disabled.

## Missing live proof

- The Sean account remains `can_read: false`, retains a stale credential path,
  and has no dedicated read OAuth token on this Mac.
- Live plugin config still points to the retired workspace path and JPop account
  and lacks the host-owned Luna completion allowlists. It was not mutated during
  this build.
- No plugin activation, Gateway restart, Gmail read, or real-email canary was
  performed.
