// Called only after signature, issuer, audience, provider and email verification.
export async function resolveVerifiedIdentity(env, claims, normalizeEmail) {
  const email = normalizeEmail(claims.email);
  if (claims.email_verified !== true || !email) return null;
  const uid = claims.sub, project = 'edgeai-auth';
  const read = () => env.DB.prepare(`SELECT u.id,u.full_name,i.revoked_at,u.is_active,
    r.email AS reserved_email,r.firebase_uid AS reserved_uid
    FROM edgeai_firebase_identities i JOIN users u ON u.id=i.user_id
    LEFT JOIN edgeai_identity_emails r ON r.user_id=u.id
    WHERE i.firebase_project=?1 AND i.firebase_uid=?2`).bind(project,uid).first();
  let known = await read();
  if (!known) {
    const approval = await env.DB.prepare('SELECT user_id FROM edgeai_email_approvals WHERE email=?1').bind(email).first();
    if (approval) {
      // Guards execute inside the transaction, including both UID and email reservations.
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO edgeai_firebase_identities(firebase_project,firebase_uid,user_id,approved_by,approved_at)
          SELECT ?1,?2,a.user_id,a.approved_by,a.approved_at FROM edgeai_email_approvals a
          JOIN users u ON u.id=a.user_id JOIN edgeai_identity_emails r ON r.user_id=a.user_id AND r.email=a.email
          WHERE a.email=?3 AND a.revoked_at IS NULL AND a.claimed_uid IS NULL AND r.firebase_uid IS NULL AND u.is_active=1
          AND NOT EXISTS(SELECT 1 FROM edgeai_firebase_identities WHERE firebase_project=?1 AND firebase_uid=?2)
          AND NOT EXISTS(SELECT 1 FROM edgeai_firebase_identities WHERE user_id=a.user_id)
          AND NOT EXISTS(SELECT 1 FROM edgeai_identity_emails WHERE firebase_uid=?2)`)
          .bind(project,uid,email),
        env.DB.prepare(`UPDATE edgeai_email_approvals SET claimed_uid=?1,claimed_at=?2 WHERE email=?3
          AND claimed_uid IS NULL AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM edgeai_firebase_identities
          WHERE firebase_project=?4 AND firebase_uid=?1 AND user_id=edgeai_email_approvals.user_id AND revoked_at IS NULL)`)
          .bind(uid,new Date().toISOString(),email,project),
        env.DB.prepare(`UPDATE edgeai_identity_emails SET firebase_uid=?1 WHERE email=?2 AND firebase_uid IS NULL
          AND EXISTS(SELECT 1 FROM edgeai_email_approvals WHERE email=?2 AND claimed_uid=?1 AND user_id=edgeai_identity_emails.user_id)`)
          .bind(uid,email)
      ]);
    } else {
      const id = 'usr_'+crypto.randomUUID();
      const name = typeof claims.name==='string' && claims.name.trim() ? claims.name.trim().slice(0,150) : 'Usuário EDGE AI';
      // All three records commit together. A racing request sees either all or none.
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO users(id,full_name,normalized_name,access_key_hash,is_active)
          SELECT ?1,?2,?3,'!firebase-only',1
          WHERE NOT EXISTS(SELECT 1 FROM edgeai_firebase_identities WHERE firebase_project=?4 AND firebase_uid=?5)
          AND NOT EXISTS(SELECT 1 FROM edgeai_identity_emails WHERE email=?6 OR firebase_uid=?5)
          AND NOT EXISTS(SELECT 1 FROM edgeai_email_approvals WHERE email=?6)
          AND NOT EXISTS(SELECT 1 FROM edgeai_firebase_identities old
            WHERE NOT EXISTS(SELECT 1 FROM edgeai_identity_emails r WHERE r.user_id=old.user_id))`)
          .bind(id,name,'firebase-'+id,project,uid,email),
        env.DB.prepare(`INSERT INTO edgeai_firebase_identities(firebase_project,firebase_uid,user_id,approved_by,approved_at)
          SELECT ?1,?2,id,'system:verified-self-registration',?3 FROM users WHERE id=?4`)
          .bind(project,uid,new Date().toISOString(),id),
        env.DB.prepare(`INSERT INTO edgeai_identity_emails(email,user_id,firebase_uid)
          SELECT ?1,id,?2 FROM users WHERE id=?3`).bind(email,uid,id)
      ]);
    }
    known = await read();
  }
  if (!known || known.revoked_at || known.is_active!==1) return null;
  // Old manually bound identities reserve their first verified email without changing ID.
  if (!known.reserved_email) {
    try {
      await env.DB.prepare(`INSERT INTO edgeai_identity_emails(email,user_id,firebase_uid) VALUES(?1,?2,?3)`)
        .bind(email,known.id,uid).run();
    } catch { /* A concurrent claim is re-read below; never overwrite a reservation. */ }
    known = await read();
  }
  if (known.reserved_email!==email || known.reserved_uid!==uid) return null;
  const reservation = await env.DB.prepare('SELECT revoked_at FROM edgeai_email_approvals WHERE user_id=?1').bind(known.id).first();
  if (reservation?.revoked_at) return null;
  return {id:known.id,full_name:known.full_name};
}
