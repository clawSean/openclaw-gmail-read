# Architecture

## Trust boundaries

1. **Gmail and message content are hostile.** OAuth remains on the Mac and must
   contain `gmail.readonly` without broader Gmail scopes.
2. **The Mac broker narrows content.** It decodes and normalizes text, removes
   active markup and hidden formatting, excludes attachments, applies bounded
   deterministic tripwires to every content-bearing field plus the assembled
   message, and emits only `SAFE` fields with a pinned broker version.
3. **The summarizer has no tools.** The plugin uses
   `api.runtime.llm.complete` with `execution.mode: isolated-agent-runtime` and
   Luna. It gets one screened message and returns one closed JSON object.
4. **Deterministic validation is authoritative.** Unknown keys, unsupported
   enums, oversized fields, raw URLs, role/control language, malformed JSON,
   non-verbatim evidence, and improperly framed requests are rejected.
5. **A fresh post-gate checks relay/fidelity.** A separate Luna completion with
   a different system prompt and no shared context compares the screened
   source with the validated candidate. `REVIEW`, `BLOCK`, malformed output,
   timeout, or outage all withhold the result.
6. **The parent receives an untrusted envelope.** Every result is labeled
   `untrustedEmailDerived: true` and `canAuthorizeActions: false`. Blocked paths
   contain no source or candidate content.

## Execution controls

- Broker path, Python executable, optional node target, and timeout come only from
  operator configuration, never tool or email input.
- With the Gateway on the Mac, the plugin executes the pinned broker locally.
  A configured node id remains an explicit remote-Mac option.
- The broker artifact SHA-256 is pinned before execution.
- The child process receives a scrubbed environment.
- Broker status, identity, version, required verdicts, and result count are
  allowlisted at the Gateway boundary.
- Audit failures are fatal; detector prose and exception text are never logged
  or returned.
- No local inference runtime is required. Deterministic tripwires are an early
  rejection layer; the isolated Luna stages and strict evidence gate contain
  attacks that do not match a known tripwire.

## Model roles

- `openai/gpt-5.6-luna`: bounded JSON transformation, followed by a fresh
  source-vs-summary relay-detector call.
- The calls have separate prompts and no shared context. Neither call has tools,
  workspace access, memory, or an agent execution loop.

The second call is defense-in-depth, not model-family independence. Capability
isolation and strict deterministic validation are the actual trust controls.
