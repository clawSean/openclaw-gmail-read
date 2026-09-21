# Activation Gate

Activation is a separate operational change. Do not treat the offline build as
live until every item below has a durable receipt.

1. Keep `plugins.entries.screened-gmail-read.enabled` false while validating.
2. Confirm the Mac account uses only `gmail.readonly` plus identity scope and
   has `can_read: true` explicitly.
3. Confirm the configured broker path matches the reviewed canonical file and
   its pinned SHA-256.
4. Confirm Ollama is local and the configured pre-detector model is installed.
5. Run both offline suites and record the commit plus test output.
6. Verify the plugin model policy explicitly allows only
   `openai/gpt-5.6-luna`.
7. Configure native completion trust under
   `plugins.entries.screened-gmail-read.llm` with
   `allowModelOverride: true`, and restrict both `allowedModels` and
   `allowedCompletionModels` to that model.
8. Prove local Gateway execution (or an explicitly configured node identity),
   append-only audit, and a maximum scope of 5 messages / 7 days.
9. Obtain explicit operator approval before the live config write or Gateway
   restart.
10. Run one synthetic benign canary, one relay canary, one malformed-output
    canary, and one detector-outage canary. The last three must fail closed.
11. Run one bounded real read on the Sean account. Confirm no raw body, URL,
    source payload, OAuth material, or detector prose appears in tool details,
    logs, or chat history.
12. Only then describe the capability as live. Extending to another account is
    a separate scope and OAuth review.

Rollback: disable the plugin entry. Preserve audit records and test receipts;
do not delete evidence during incident review.
