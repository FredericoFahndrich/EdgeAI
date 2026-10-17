# Live Firebase suspension and revocation — 3.0.2

The Worker queries the fixed Firebase `accounts:lookup` endpoint on every protected request. A D1 cookie alone no longer authorizes access. Firebase suspension, deletion, unverified/changed email or token revocation denies the next request as soon as Firebase reports that state. Successful results are never cached across requests; duplicate authentication checks within the same request share one promise.

The lookup uses the existing public Web API key and that user's signed ID token. It does not need a service-account key or IAM permissions. The Worker validates issuer, audience, signature, provider and expiry before trusting claims, then compares UID/email and `auth_time` with live `validSince`. It records the Firebase account creation timestamp on first live login; a later account reusing that UID with a different creation timestamp cannot adopt the old D1 identity.

## Session protection

- A second `__Host-edgeai_firebase` cookie is Secure, HttpOnly, SameSite=Lax and host-only. It is limited to 3800 bytes and expires with the ID token. Tokens are never stored in plaintext in D1, URLs, responses or logs.
- The D1 session hash binds both the random session secret and the exact Firebase token. Removing/replacing either cookie fails authorization. Old single-cookie sessions must reconnect through Firebase; existing users/data/memberships are unchanged.
- A confirmed invalid Firebase session revokes the matching D1 session. Re-enabling an account does not revive that revoked cookie. A fresh authorized login can create a new session for the same preserved user ID.
- Firebase network/HTTP/schema failures return 503 and block access, while preserving D1 users, identities, memberships and session records for recovery. Logout works even during a provider outage and expires both cookies.
- Chat is rechecked after long model calls before private output is saved or returned. Existing downloads/data already delivered before revocation cannot be recalled. Authorization has no expiry grace period; it operates on each request, not a permanent connection.
- The UI checks session status every 15 seconds and on focus, clearing private cached state when the session is invalid or cannot be checked. Server denial applies independently of this UI interval.

## Data and migration

`0004_firebase_account_origins.sql` adds only a UID/account-creation metadata table and a migration record. It never updates/deletes users, memberships, approvals, conversation history or files. A fresh private D1 backup is restored in memory, foreign keys checked and all original table data fingerprinted before applying it remotely.

## Tests before publication

`npm test`: 95 backend tests and 15 UI tests. New cases cover suspension on the next request, revocation of an unexpired token, `auth_time` versus refreshed `iat`, provider outages/malformed metadata, missing/substituted cookies, recycled UID, reauthentication with preserved user ID and revocation during model inference. Prior isolation and membership tests remain included.

`npm run test:firebase-emulator`: four tests against the official local Auth emulator using a demo project. The same issued token is accepted while active and denied after disabling, setting `validSince` and deleting the emulated account. Production accounts and credentials are not used. CI runs both suites before release.

Before publication, the candidate Worker was also tested against real Firebase with an isolated synthetic local D1 database. The ordinary test account authenticated, was temporarily disabled in Firebase, and its existing session was denied without waiting for token expiry. The account was restored; its revoked cookie remained denied. No production D1 data or project membership was changed by that test. Production smoke checks real sign-in and preserved account access after publication.

## Release and rollback

1. Validate fresh private backup and record the current Worker version/D1 bookmark.
2. Apply only additive migration 0004; publish the tested Worker with the reviewed frontend SHA.
3. Reconnect admin and ordinary accounts; verify their existing IDs, personal/project isolation and Firebase lookup behavior.
4. Verify the prepublication real suspension evidence and account restoration; require fresh login after a revoked session. Preserve all memberships and data.
5. Merge after CI and smoke checks. Check Pages and leave the app logged out.

Rollback to 3.0.1 restores the prior Firebase-only revocation limitation; therefore it is an availability recovery action, not a security-equivalent fallback. Keep the additive origins table and all user data. Do not restore the entire D1 backup over later production writes.

References: [Firebase REST account lookup](https://firebase.google.com/docs/reference/rest/auth#get_user_data), [Firebase session revocation](https://firebase.google.com/docs/auth/admin/manage-sessions), [official Admin SDK comparison of auth_time and validSince](https://github.com/firebase/firebase-admin-node/blob/master/src/auth/base-auth.ts).
