# Google Cloud OAuth Handoff

This is the only browser-side setup JPop must perform for the Sean read lane.
The Google Cloud project may be new or existing. The OAuth client must be new.

## Required Google configuration

1. Select a Google Cloud project controlled by JPop or Sean.
2. Enable **Gmail API** for that project.
3. Configure the OAuth consent screen as External and Testing for the bounded
   pilot unless the project already has an appropriate production consent
   screen.
4. Add Sean's Google account as a test user while the app is in Testing.
5. Create a new OAuth client: **Desktop app**.
6. Name it `gmail-read-sean`.
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

After JPop supplies the downloaded Desktop client JSON locally, Sean runs the
PKCE bootstrap with the expected Sean account. The bootstrap:

- requests only `gmail.readonly`, `openid`, and `userinfo.email`;
- verifies the account that approved consent;
- refuses a client id already used by a Gmail-send credential;
- writes private files under `~/.openclaw/credentials/gmail-read-sean/`;
- never prints tokens.

The downloaded source JSON is moved to Trash after the private verified copy is
written. OAuth completion does not activate the plugin or permit email reads.

## Activation boundary

After OAuth, Sean runs `scripts/activation_preflight.py --phase prepare` and
shows the secret-free receipt. A separate explicit approval is still required
before setting `can_read: true`, enabling the plugin, applying live config, or
performing the bounded real-email canary.
