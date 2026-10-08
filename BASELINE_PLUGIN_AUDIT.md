# Baseline Plugin Audit

Date: 2026-10-08

## Identity and source

- Plugin id: `mailreef`
- Version: `0.6.0`
- Canonical source: `mailreef-plugin/`
- Published source: `clawSean/mailreef` (`main`; exact head recorded in AID
  status/log after publication)
- Runtime discovery is deferred until the separately approved activation
  migration; the retired plugin identity remains disabled.
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
- `npm --prefix mailreef-plugin run check`: passed.
- Email skill baseline: 9/9 passed.
- Python compilation and `git diff --check`: passed.
- Email policy baseline: 9/9 passed.
- Gitleaks: passed with no leaks.
- `openclaw config validate --json`: valid through the frozen disabled
  `65a3eff` rollback worktree; live config was not mutated.
- Offline activation preflight correctly reports the remaining host-config and
  OAuth blockers without exposing credential values.
- Live OpenClaw discovery for `mailreef` is intentionally not configured yet.

## Missing live proof

- The Sean account remains `can_read: false` and has no dedicated Mailreef OAuth
  token on this Mac.
- Live config still contains the disabled retired plugin identity and lacks the
  Mailreef source path and host-owned Luna completion allowlists. It was not
  mutated during this rename.
- No plugin activation, Gateway restart, Gmail read, or real-email canary was
  performed.
