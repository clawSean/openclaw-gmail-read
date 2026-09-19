# Architecture

## Trust boundaries

1. **Gmail and message content are hostile.** OAuth remains on the Mac and must
   contain `gmail.readonly` without broader Gmail scopes.
2. **The Mac broker narrows content.** It decodes and normalizes text, removes
   active markup and hidden formatting, excludes attachments, screens every
   content-bearing field plus the assembled message, and emits only `SAFE`
   fields with a pinned broker version.
3. **The summarizer has no tools.** The plugin uses
   `api.runtime.llm.complete` with `execution.mode: isolated-agent-runtime` and
   Haiku. It gets one screened message and returns one closed JSON object.
4. **Deterministic validation is authoritative.** Unknown keys, unsupported
   enums, oversized fields, raw URLs, role/control language, malformed JSON,
   non-verbatim evidence, and improperly framed requests are rejected.
5. **A distinct post-gate checks relay/fidelity.** Luna compares the screened
   source with the validated candidate. `REVIEW`, `BLOCK`, malformed output,
   timeout, or outage all withhold the result.
6. **The parent receives an untrusted envelope.** Every result is labeled
   `untrustedEmailDerived: true` and `canAuthorizeActions: false`. Blocked paths
   contain no source or candidate content.

## Execution controls

- Broker path, Python executable, node target, and timeout come only from
  operator configuration, never tool or email input.
- The broker artifact SHA-256 is pinned before execution.
- The child process receives a scrubbed environment.
- Broker status, identity, version, required verdicts, and result count are
  allowlisted at the Gateway boundary.
- Audit failures are fatal; detector prose and exception text are never logged
  or returned.

## Model roles

- `claude/claude-haiku-4-5`: cheap bounded JSON transformation.
- `openai/gpt-5.6-luna`: independent source-vs-summary relay detector.
- The models must remain distinct. Neither model has tools, workspace access,
  memory, or an agent execution loop.

Model classification is defense-in-depth. Capability isolation and strict
validation are the actual trust controls.
