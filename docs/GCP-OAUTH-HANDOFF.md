# Google Cloud OAuth Handoff

This is the only browser-side setup JPop must perform for the Sean read lane.
The Google Cloud project may be new or existing. The OAuth client must be new.

**Completed 2026-10-08:** project `sean-mailreef`, Gmail API, External/Testing
consent, exact read-plus-identity scopes, Sean test user, and separate Desktop
client `mailreef-sean`. The client JSON was downloaded on JPop's computer; it
has not yet been transferred to ClawPop or used for OAuth.

## Required Google configuration

1. Create a dedicated project named **Sean Mailreef**. Use a globally unique
   project id such as `sean-mailreef-<suffix>`.
2. Enable **Gmail API** for that project.
3. Configure the OAuth consent screen as External and Testing for the bounded
   pilot unless the project already has an appropriate production consent
   screen.
4. Add Sean's Google account as a test user while the app is in Testing.
5. Create a new OAuth client: **Desktop app**.
6. Name it `mailreef-sean`.
7. Download its client JSON to the Mac.

Do not reuse any Gmail-send, Drive, Calendar, browser, web-app, or installed-app
client. Do not create an API key or service account; neither is used here.

`gmail.readonly` is a Google restricted scope. In External/Testing mode, this
grant expires after seven days because it includes more than basic identity
scopes. That is acceptable for the bounded pilot, not durable operation. Before
calling the lane durable, move the consent screen to Production under Google's
documented personal-use exception or complete whatever verification Google then
requires. Do not broaden scopes to avoid that process.

## Sean's local handoff

After JPop transfers the downloaded Desktop client JSON to ClawPop through a
private local route, Sean runs the PKCE bootstrap with expected account
`seancrustacean@gmail.com`. The bootstrap:

- requests only `gmail.readonly`, `openid`, and `userinfo.email`;
- verifies the account that approved consent;
- refuses a client id already used by a Gmail-send credential;
- writes private files under `~/.openclaw/credentials/mailreef-sean/`;
- never prints tokens.

The downloaded source JSON is moved to Trash after the private verified copy is
written. OAuth completion does not activate the plugin or permit email reads.

## Activation boundary

After OAuth, Sean runs `scripts/activation_preflight.py --phase prepare` and
shows the secret-free receipt. A separate explicit approval is still required
before setting `can_read: true`, enabling the plugin, applying live config, or
performing the bounded real-email canary.
