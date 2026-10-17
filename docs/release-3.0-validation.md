# EDGE AI 3.0 — release validation

## Preserved baseline

Before migration, the private export restored successfully in memory: integrity check OK, zero foreign-key violations, four users, four Solar memberships, 17 conversations and 110 messages. Applying migration 0003 twice did not change original table data. The production baseline matched those counts before the remote migration.

Migration 0003 was applied remotely after backup validation and recording a Time Travel bookmark. The post-migration counts and foreign-key check were unchanged. A later read-only comparison against the private backup verified that every original row in users, projects, memberships, email approvals, Firebase identities, project files/documents, messages and conversations remained unchanged. Test operations add personal records; they do not replace original records.

## Local and CI validation

- 74 backend tests with RSA-signed Firebase fixtures and real SQLite transactions.
- 12 UI tests for login coordination, refresh, logout, stale responses and health status.
- Worker package validated with Wrangler. Existing secret names, non-secret variables and D1/R2 bindings verified after deployment. Preview URLs explicitly disabled.

## Production E2E

- Existing administrator signed in with Google and retained D1 identity `usr_frederico`, the administrative panel, original Solar memberships, old Solar conversations and four project documents. The pending legacy email approval remained pending.
- A new personal administrator conversation received `EDGEAI30-ADMIN-OK` from the real AI service and persisted after reload. A synthetic administrator personal file was uploaded into R2.
- A verified ordinary Google account automatically received a new D1 identity with zero project memberships. Its project list was empty, its administrative UI was absent and its server session reported `is_admin:false`.
- Direct ordinary-account requests were denied for administrative data, Solar access/files/members and a known Solar download. Requests for the administrator's personal conversation and personal file were also denied.
- The ordinary account received `EDGEAI30-COMUM-OK` from the real AI service. Its conversation and personal file persisted after reload. Upload/download content matched by SHA-256.
- Administrative logout returned an unauthenticated server session. Final ordinary logout and Pages propagation are verified as part of release completion.

The real-account flows used Google; password-provider JWT handling, suspension/revocation, transactional races and non-admin-owner mutations were validated locally. No project memberships were granted to test accounts. Synthetic personal test conversations/files were retained. No ID tokens, cookies, private export or real UID/email mapping is committed here.

## Boundaries

Email changes and identity relinking are intentionally denied by automatic registration and require reviewed recovery. D1 suspension/revocation blocks server requests immediately. Firebase-only token revocation is not queried through Firebase Admin and takes effect no later than token/session expiry. See [policy and rollback](verified-registration.md).
