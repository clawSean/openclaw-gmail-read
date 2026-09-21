# Activation Gate

Activation is a separate operational change. Do not treat the offline build as
live until every item below has a durable receipt.

1. Keep `plugins.entries.screened-gmail-read.enabled` false while validating.
2. Confirm the Mac account uses only `gmail.readonly` plus identity scope and
   has `can_read: true` explicitly.
3. Confirm the configured broker path matches the reviewed canonical file and
   its pinned SHA-256.
4. Create the token with `scripts/bootstrap_gmail_read_oauth.py`; verify the
   approving identity, exact scope set, private file modes, and separate
   `gmail-read-sean` credential directory. Move the downloaded source JSON to
   Trash after the verified private copy exists.
5. Confirm the read plugin cannot access any `gmail.send` credential directory.
6. Run both offline suites and record the commit plus test output.
7. Verify the plugin model policy explicitly allows only
   `openai/gpt-5.6-luna`.
8. Configure native completion trust under
   `plugins.entries.screened-gmail-read.llm` with
   `allowModelOverride: true`, and restrict both `allowedModels` and
   `allowedCompletionModels` to that model.
9. Prove local Gateway execution (or an explicitly configured node identity),
   append-only audit, and a maximum scope of 5 messages / 7 days.
10. Obtain explicit operator approval before the live config write or Gateway
   restart.
11. Run one synthetic benign canary, one relay canary, one malformed-output
    canary, and one model-outage canary. The last three must fail closed.
12. Run one bounded real read on the Sean account. Confirm no raw body, URL,
    source payload, OAuth material, or detector prose appears in tool details,
    logs, or chat history.
13. Only then describe the capability as live. Extending to another account is
    a separate scope and OAuth review.

Rollback: disable the plugin entry. Preserve audit records and test receipts;
do not delete evidence during incident review.
