# EDGE AI 3.0 — verified personal access

Firebase Google/password users with a signed `edgeai-auth` token, supported provider and `email_verified=true` can obtain a personal D1 identity. User names, request body IDs and declared emails never authorize access. Personal conversations, PDF context and R2 documents require the D1 session owner. Projects remain membership-only, including for the global administrator's content access.

## Identity rules

- Existing UID bindings and D1 user IDs are preserved. An existing email approval can bind only its selected user. Pending, suspended, consumed and revoked reservations block a second UID.
- `0003_verified_self_registration.sql` adds an email/UID/user reservation table, approval reservation triggers and personal document storage metadata. It does not grant memberships or replace existing rows.
- New users, UID bindings and email reservations commit in one D1 batch. Unique constraints and SQL predicates enforce concurrency. `normalized_name` uses a generated user ID, while display names can repeat. Password hashes contain a disabled Firebase-only sentinel; legacy password login remains disabled.
- The first verified login of an old manually bound identity reserves its email. Automatic creation fails closed until all old UID bindings have email reservations. This prevents a new UID from reserving the administrator's email during the cutover. After the migration, sign in as the existing administrator before testing a newcomer.
- Suspension/revocation is checked on requests through active users, session and identity bindings. Revoked records and email reservations remain as tombstones. Automatic email changes/relinking are denied and need an explicit reviewed recovery process.
- Firebase JWT signature verification does not independently perform a Firebase Admin `checkRevoked` lookup. D1 suspension/revocation takes effect immediately; an external Firebase-only revocation can remain usable until the issued token/session expires (at most its signed expiry). No service-account credentials were added.

## Membership management

`GET/PATCH /projects/:id/members` requires a global administrator or an owner of that project. Owners can add/remove editors by their existing EDGE AI user ID. Only the global administrator assigns/replaces owners. Owners cannot change themselves, the administrator or another owner. The SQL write rechecks active actor, owner membership and target role; the change and audit event share one batch. This prevents an owner of one project from granting roles in another project. The UI only exposes that project's member list; it does not expose a global user directory to owners.

The global administrative panel retains approval of legacy members, status/revocation and membership controls. New verified accounts need no approval for their personal workspace. A person's ID is visible in Account and access for sharing with a project owner.

## Personal files

`/me/files` uses the authenticated user ID on the server. Clients cannot select another owner. Objects use `personal/<user-id>/<random-id>`; listing, download and delete require that same user. Project files keep their prior routes and membership policy. The existing 15 MB/type limits, bounded multipart parser and private no-store downloads apply. Stored files do not automatically enter AI context; PDF analysis uses the separate authenticated upload flow.

## Tests

`npm test`: 74 backend cases with signed RSA JWTs and real in-memory SQLite transactions, plus 12 UI coordination cases. Covers personal/project isolation, reserved emails, suspended/revoked identities, repeat display names, duplicate concurrent exchanges, competing UIDs, rollback after an injected failure, owner scoping, concurrent owner removal, personal R2 bytes, session cleanup and health reporting during login refresh. These are local tests; real Firebase/R2/OpenAI E2E must also pass before merge.

## Release and rollback

1. Validate a private D1 export by restoring it in memory; validate integrity, foreign keys and old-table data fingerprints before/after 0003. Compare production baseline counts. Keep the backup outside Git.
2. Record the current D1 Time Travel bookmark and active Worker version. Apply only 0003; 0001/0002 are already present remotely. Use `wrangler d1 execute edgeai-db --remote --file backend/migrations/0003_verified_self_registration.sql`.
3. Push the reviewed frontend commit and pin `/app` to its immutable SHA. Validate `wrangler deploy --dry-run`. Deploy the Worker with preserved existing variables/secrets and unchanged D1/R2 bindings.
4. Sign in with the existing administrator to reserve the old verified identity. Confirm four original user IDs and Solar memberships, pending legacy approval and historical content. Sign in with a newcomer; confirm empty projects, personal chat/files and denied Solar/admin access. Reload to verify persistence and logout to verify denial.
5. After E2E and CI pass, merge the PR and verify Pages redirects to the working `/app` authentication origin.

For application rollback, redeploy the prior Worker version and prior pinned frontend. Leave additive 0003 tables/triggers in place; do not drop user data. Automatic accounts already created retain their data, but the old Worker may no longer give them sessions. Restoring the entire D1 database is an emergency action requiring a separately reviewed outage/data-loss decision, because it would discard writes after the bookmark. Never import the backup over production as an ordinary rollback.
