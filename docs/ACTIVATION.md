# Activation Gate

Activation is a separate operational change. Do not treat the offline build as
live until every item below has a durable receipt.

1. Keep `plugins.entries.mailreef.enabled` false while validating.
2. Confirm the Mac account uses only `gmail.readonly` plus identity scope and
   has `can_read: true` explicitly.
   Google may report the identity alias `email` in addition to `openid` and
   `userinfo.email`; normalize only that alias and reject every other extra
   scope.
3. Confirm the configured broker path matches the reviewed canonical file and
   its pinned SHA-256.
4. Create the token with `scripts/bootstrap_mailreef_oauth.py`; verify the
   approving identity, exact scope set, private file modes, and separate
   `mailreef-sean` credential directory. The bootstrap must create/update the
   account registry with `can_read: false`. Move the downloaded source JSON to
   Trash after the verified private copy exists.
   When consent runs in a JPop-controlled browser on another Tailscale device,
   use `--callback-bind <ClawPop-Tailscale-IP> --no-browser --auth-url-out
   <private-file>`; keep the registered redirect URI on loopback and relay the
   resulting query directly over Tailscale without printing or copying it.
5. Confirm the read plugin cannot access any `gmail.send` credential directory.
6. Run both offline suites and record the commit plus test output.
7. Run `python3 scripts/activation_preflight.py --phase prepare`; require a
   secret-free `status: ready` receipt before any activation mutation.
8. Verify the plugin model policy explicitly allows only
   `openai/gpt-5.6-luna`.
9. Configure native completion trust under
   `plugins.entries.mailreef.llm` with
   `allowModelOverride: true`, and restrict both `allowedModels` and
   `allowedCompletionModels` to that model.
10. Prove local Gateway execution (or an explicitly configured node identity),
    append-only audit, and both bounded modes:
    - recent triage: at most 5 messages / 7 days;
    - historical discovery: at most 10 IDs/timestamps, one 366-day window,
      10-year age floor, structured sender/subject filters, inbox-only, no
      pagination, no email-authored prose, and zero model calls.
11. Obtain explicit operator approval before the live config write or Gateway
   restart.
12. Run one synthetic benign canary, one relay canary, one malformed-output
    canary, and one model-outage canary. The last three must fail closed.
13. Run `python3 scripts/activation_preflight.py --phase live`, then one bounded
    real historical discovery and one selected-message read on the Sean account.
    Confirm discovery returns only IDs/timestamps and no raw body, URL,
    source payload, OAuth material, or detector prose appears in tool details,
    logs, or chat history.
14. Only then describe the capability as live. Extending to another account is
    a separate scope and OAuth review. For a secondary account while Mailreef is
    already live, keep the new registry row `can_read: false` and absent from
    `allowedAccounts`, then run `--phase account_prepare --account <label>`.
    After explicit activation, atomically set `can_read: true`, add only that
    label to `allowedAccounts`, hot-reload, and require `--phase live --account
    <label>` plus bounded canaries. The existing default account stays live.

Rollback: disable the plugin entry. Preserve audit records and test receipts;
do not delete evidence during incident review.
