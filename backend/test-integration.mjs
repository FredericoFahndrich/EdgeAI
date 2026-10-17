import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DatabaseSync} from 'node:sqlite';
import worker from './worker.mjs';
const db=new DatabaseSync(':memory:');
db.exec(`PRAGMA foreign_keys=ON;
CREATE TABLE users(id TEXT PRIMARY KEY,full_name TEXT NOT NULL,normalized_name TEXT UNIQUE NOT NULL,access_key_hash TEXT NOT NULL,is_active INTEGER NOT NULL CHECK(is_active IN (0,1)));
CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT);
CREATE TABLE project_members(project_id TEXT,user_id TEXT,role TEXT,PRIMARY KEY(project_id,user_id));
CREATE TABLE user_sessions(id TEXT PRIMARY KEY,user_id TEXT,token_hash TEXT UNIQUE,expires_at TEXT,revoked_at TEXT);
CREATE TABLE auth_login_limits(client_key TEXT PRIMARY KEY,window_minute INTEGER,attempts INTEGER);
CREATE TABLE conversations(id TEXT PRIMARY KEY,user_name TEXT,created_at TEXT,updated_at TEXT,project_id TEXT,created_by_user_id TEXT,title TEXT,is_archived INTEGER DEFAULT 0);
CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,conversation_id TEXT,role TEXT,content TEXT,created_at TEXT,sender_user_id TEXT);
INSERT INTO users VALUES('owner','Owner','owner','disabled',1),('editor','Editor','editor','disabled',1),('outsider','Outsider','outsider','disabled',1);
INSERT INTO projects VALUES('prj_solar','Solar');
INSERT INTO project_members VALUES('prj_solar','owner','owner'),('prj_solar','editor','editor');
INSERT INTO conversations VALUES('private_owner','Owner','2026','2026',NULL,'owner','Private',0),('shared','Owner','2026','2026','prj_solar','owner','Shared',0),('legacy_guest','Guest','2026','2026',NULL,NULL,'Guest',0);
INSERT INTO messages(conversation_id,role,content,created_at) VALUES('private_owner','user','PRIVATE_SECRET','2026');`);
const migration=fs.readFileSync(new URL('migrations/0001_firebase_identity.sql',import.meta.url),'utf8');db.exec(migration);db.exec(migration);
const adminMigration=fs.readFileSync(new URL('migrations/0002_email_access_admin.sql',import.meta.url),'utf8');db.exec(adminMigration);db.exec(adminMigration);
const selfMigration=fs.readFileSync(new URL('migrations/0003_verified_self_registration.sql',import.meta.url),'utf8');db.exec(selfMigration);db.exec(selfMigration);
const liveMigration=fs.readFileSync(new URL('migrations/0004_firebase_account_origins.sql',import.meta.url),'utf8');db.exec(liveMigration);db.exec(liveMigration);
for(const id of ['owner','editor','outsider']) db.prepare('INSERT INTO edgeai_firebase_identities VALUES(?,?,?,?,?,NULL)').run('edgeai-auth','uid-'+id,id,'fixture-admin','2026-01-01');
let transactionQueue=Promise.resolve();
const DB={prepare(sql){const st=db.prepare(sql);let args=[];return {bind(...a){args=a;return this;},params(){return Object.fromEntries(args.map((v,i)=>[i+1,v]));},async first(){return st.get(this.params())||null;},async all(){return {results:st.all(this.params())};},async run(){const r=st.run(this.params());return {meta:{changes:Number(r.changes),last_row_id:Number(r.lastInsertRowid)}};}};},async batch(sts){const job=transactionQueue.then(async()=>{db.exec('BEGIN');try{const out=[];for(const st of sts)out.push(await st.run());db.exec('COMMIT');return out;}catch(e){db.exec('ROLLBACK');throw e;}});transactionQueue=job.catch(()=>{});return job;}};
const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
const jwk=await crypto.subtle.exportKey('jwk',pair.publicKey);jwk.kid='test-key';
let providerCalls=0,keyCalls=0,liveCalls=0;
const firebaseAccounts=new Map();let firebaseLookupMode='ok',beforeModelReturn=null;
const fixtureCreatedAt=String((Math.floor(Date.now()/1000)-86400)*1000);
function cookiePair(response){return response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');}
globalThis.fetch=async(url,options)=>{
  if(String(url).startsWith('https://raw.githubusercontent.com/FredericoFahndrich/EdgeAI/')) {
    assert.match(String(url),/\/EdgeAI\/[0-9a-f]{40}\/index\.html$/);
    return new Response('<head><title>Fixture pinned frontend</title></head>');
  }
  if(String(url).includes('/service_accounts/v1/jwk/')) {keyCalls++;return Response.json({keys:[jwk]},{headers:{'Cache-Control':'max-age=300'}});}
  if(String(url).startsWith('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=')) {
    liveCalls++;assert.equal(options.redirect,'manual');assert.equal(options.headers['Cache-Control'],'no-store');
    const {idToken}=JSON.parse(options.body),claims=JSON.parse(Buffer.from(idToken.split('.')[1],'base64url'));
    if(firebaseLookupMode==='network')throw Error('Fixture network failure');
    if(firebaseLookupMode==='outage')return Response.json({error:{message:'UNAVAILABLE'}},{status:503});
    if(firebaseLookupMode==='bad-key')return Response.json({error:{message:'API_KEY_INVALID'}},{status:400});
    if(firebaseLookupMode==='malformed')return Response.json({unexpected:true});
    const overrides=firebaseAccounts.get(claims.sub)||{};
    if(overrides.error)return Response.json({error:{message:overrides.error}},{status:400});
    if(overrides.deleted)return Response.json({users:[]});
    return Response.json({users:[{localId:claims.sub,email:claims.email,emailVerified:true,validSince:'0',createdAt:fixtureCreatedAt,...overrides}]});
  }
  providerCalls++;
  if(String(url).endsWith('/v1/files'))return Response.json({id:'file-fixture'});
  if(String(url).endsWith('/v1/responses')){if(beforeModelReturn)await beforeModelReturn();return Response.json({output_text:JSON.stringify({message:'Fixture answer',linkedin_action:{required:false}})});}
  throw Error('Unexpected outbound');
};
const bucket=new Map();const env={DB,OPENAI_API_KEY:'fixture',FILES_BUCKET:{async put(k,b){bucket.set(k,b);},async get(k){const b=bucket.get(k);return b?{body:b,size:b.byteLength}:null;},async delete(k){bucket.delete(k);}}};
const base='https://edgeai-backend.frederico-fahndrich.workers.dev';let ip=0;
async function req(path,{method='GET',cookie,body,origin=base,raw,guest}={}){
  const headers={Origin:origin,'CF-Connecting-IP':String(++ip)};
  if(cookie) headers.Cookie=cookie;if(guest)headers['X-EdgeAI-Guest']='a'.repeat(64);
  if(body!==undefined)headers['Content-Type']='application/json';
  return worker.fetch(new Request(base+path,{method,headers,...(body!==undefined?{body:JSON.stringify(body)}:raw?{body:raw}:{})}),env,{waitUntil(){}});
}
async function token(uid='uid-owner',overrides={},head={}){
  const now=Math.floor(Date.now()/1000);
  const enc=v=>Buffer.from(JSON.stringify(v)).toString('base64url');
  const data=enc({alg:'RS256',kid:'test-key',...head})+'.'+enc({iss:'https://securetoken.google.com/edgeai-auth',aud:'edgeai-auth',sub:uid,iat:now-5,auth_time:now-60,exp:now+3500,firebase:{sign_in_provider:'google.com'},email:uid+'@example.invalid',email_verified:true,...overrides});
  return data+'.'+Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,new TextEncoder().encode(data))).toString('base64url');
}
let passed=0;async function check(name,fn){await fn();passed++;console.log('PASS '+name);}
async function expect(path,opts,status){const r=await req(path,opts);assert.equal(r.status,status,await r.clone().text());return r;}
await check('additive migration idempotent, preserves members and conversations',async()=>{assert.equal(db.prepare('SELECT count(*) n FROM project_members').get().n,2);assert.equal(db.prepare('SELECT count(*) n FROM conversations').get().n,3);});
await check('app serves immutable frontend with correct asset base',async()=>{const r=await expect('/app',{},200);assert.match(await r.text(),/<base href="https:\/\/fredericofahndrich.github.io\/EdgeAI\/">/);assert.equal(r.headers.get('Cache-Control'),'no-store');});
for(const path of ['/chat','/upload?mode=public','/projects','/me/conversations','/projects/prj_solar/files'])for(const guest of [false,true])await check('anonymous and guest denied '+path+' '+guest,async()=>{const before=providerCalls;await expect(path,{method:path==='/chat'||path.startsWith('/upload')?'POST':'GET',body:path==='/chat'?{message:'test',mode:'public'}:undefined,guest},401);assert.equal(providerCalls,before);});
for(const [name,claims,head] of [['aud',{aud:'wrong'}],['issuer',{iss:'wrong'}],['expiry',{exp:1}],['future iat',{iat:9999999999}],['auth_time',{auth_time:9999999999}],['empty subject',{sub:''}],['provider',{firebase:{sign_in_provider:'custom'}}],['tenant',{firebase:{sign_in_provider:'google.com',tenant:'x'}}],['algorithm',{}, {alg:'HS256'}],['unknown key',{}, {kid:'unknown'}]]) await check('reject '+name,async()=>{await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-owner',claims,head)}},401);});
await check('tampered signature rejected',async()=>{let t=await token();t=t.slice(0,-20)+'a'.repeat(20);await expect('/auth/firebase',{method:'POST',body:{idToken:t}},401);});
await check('unapproved UID cannot claim by name/email/user_id',async()=>{await expect('/auth/firebase',{method:'POST',body:{idToken:await token('not-approved',{email:'owner@example.invalid',email_verified:false,name:'Owner'}),user_id:'owner'}},403);assert.equal(db.prepare('SELECT count(*) n FROM user_sessions').get().n,0);});
await check('cross origin exchange rejected',()=>expect('/auth/firebase',{method:'POST',origin:'https://fredericofahndrich.github.io',body:{idToken:'bad'}},403));
const sessions={};for(const id of ['owner','editor','outsider'])await check('verified exchange '+id,async()=>{const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-'+id)}},200);sessions[id]=cookiePair(r);assert.match(r.headers.get('set-cookie'),/HttpOnly; Secure; SameSite=Lax/);const s=await expect('/auth/session',{cookie:sessions[id]},200);assert.equal((await s.json()).user.id,id);});
await check('authenticated former-public PDF upload uses backend owner',async()=>{const form=new FormData();form.append('file',new File(['%PDF-1.4 fixture'],'fixture.pdf',{type:'application/pdf'}));await expect('/upload?mode=public',{method:'POST',cookie:sessions.owner,raw:form},200);assert.equal(db.prepare('SELECT owner_key FROM edgeai_pdf_owners WHERE file_id=?').get('file-fixture').owner_key,'user:owner');});
await check('public chat now owned by backend user',async()=>{await expect('/chat',{method:'POST',cookie:sessions.owner,body:{message:'Fixture',mode:'public',conversation_id:'new_personal'}},200);assert.equal(db.prepare('SELECT created_by_user_id FROM conversations WHERE id=?').get('new_personal').created_by_user_id,'owner');});
await check('legacy guest conversation never adopted',()=>expect('/chat',{method:'POST',cookie:sessions.owner,body:{message:'Fixture',mode:'public',conversation_id:'legacy_guest'}},403));
await check('personal read isolated',()=>expect('/me/conversations/private_owner/messages',{cookie:sessions.editor},404));
await check('personal chat isolated',()=>expect('/chat',{method:'POST',cookie:sessions.editor,body:{message:'Fixture',conversation_id:'private_owner',mode:'public'}},403));
for(const id of ['owner','editor'])await check('existing Solar access '+id,()=>expect('/projects/prj_solar/conversations/shared/messages',{cookie:sessions[id]},200));
await check('nonmember denied Solar',()=>expect('/projects/prj_solar/conversations/shared/messages',{cookie:sessions.outsider},403));
await check('PDF owner checked',async()=>{db.prepare("INSERT INTO edgeai_pdf_owners VALUES('file-private','user:owner','2026')").run();const before=providerCalls;await expect('/chat',{method:'POST',cookie:sessions.editor,body:{message:'Fixture',mode:'public',file_ids:['file-private']}},403);assert.equal(providerCalls,before);});
await check('old password login disabled',()=>expect('/auth/login',{method:'POST',body:{user_name:'Owner',access_key:'test'}},410));
await check('old sessions cannot bypass Firebase',async()=>{const raw='b'.repeat(43);const hash=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(raw))).toString('hex');db.prepare('INSERT INTO user_sessions VALUES(?,?,?,?,NULL)').run('old','owner',hash,'2099-01-01');await expect('/projects',{cookie:'edgeai_session='+raw},401);});
await check('binding revocation immediately denies existing session',async()=>{db.exec("UPDATE edgeai_firebase_identities SET revoked_at='2026' WHERE user_id='editor'");await expect('/projects',{cookie:sessions.editor},401);});
await check('logout revokes server session',async()=>{await expect('/auth/logout',{method:'POST',cookie:sessions.owner},200);await expect('/projects',{cookie:sessions.owner},401);});
await check('deactivated user denied',async()=>{db.exec("UPDATE users SET is_active=0 WHERE id='outsider'");await expect('/projects',{cookie:sessions.outsider},401);});
db.exec("INSERT INTO users VALUES('usr_frederico','Administrator','admin','disabled',1),('usr_legacy','Existing member','existing-member','disabled',1); INSERT INTO project_members VALUES('prj_solar','usr_legacy','editor');");
db.prepare('INSERT INTO edgeai_firebase_identities VALUES(?,?,?,?,?,NULL)').run('edgeai-auth','uid-admin','usr_frederico','approved fixture','2026-01-01');
let adminCookie;
await check('admin role derives from verified D1 identity',async()=>{const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-admin')}},200);adminCookie=cookiePair(r);const session=await expect('/auth/session',{cookie:adminCookie},200);assert.equal((await session.json()).user.is_admin,true);});
for(const method of ['GET','POST','PATCH'])await check('nonadministrator cannot call admin API '+method,async()=>{await expect('/admin/access',{method,cookie:sessions.owner,body:method==='GET'?undefined:{is_admin:true}},401);await expect('/admin/access',{method,cookie:adminCookie,origin:'https://fredericofahndrich.github.io',body:method==='GET'?undefined:{}},403);});
// Owner cookie above was logged out; an active editor proves an authenticated denial.
const active=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-owner')}},200);const ordinaryCookie=cookiePair(active);
await check('active ordinary user receives 403 for admin data and mutations',async()=>{await expect('/admin/access',{cookie:ordinaryCookie},403);await expect('/admin/users',{method:'POST',cookie:ordinaryCookie,body:{email:'not-allowed@example.invalid',existing_user_id:'usr_legacy',is_admin:true}},403);});
await check('admin listing contains no credential hashes or session tokens',async()=>{const r=await expect('/admin/access',{cookie:adminCookie},200);const data=await r.json();assert(data.users.some(u=>u.id==='usr_legacy'));for(const u of data.users){assert(!('access_key_hash' in u));assert(!('firebase_uid' in u));}});
await check('approve explicit email for existing user preserves membership',async()=>{await expect('/admin/users',{method:'POST',cookie:adminCookie,body:{email:'Invited@example.invalid',existing_user_id:'usr_legacy'}},201);assert.equal(db.prepare('SELECT role FROM project_members WHERE user_id=?').get('usr_legacy').role,'editor');assert.equal(db.prepare('SELECT count(*) n FROM edgeai_admin_audit').get().n,1);});
await check('unverified or unapproved email cannot claim identity',async()=>{for(const overrides of [{email:'invited@example.invalid',email_verified:false}])await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-invited',overrides)}},403);assert.equal(db.prepare('SELECT count(*) n FROM edgeai_firebase_identities WHERE user_id=?').get('usr_legacy').n,0);});
let invitedCookie;
await check('verified approved email claims exactly its administratively selected user',async()=>{const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-invited',{email:'INVITED@example.invalid',email_verified:true})}},200);invitedCookie=cookiePair(r);assert.equal((await r.json()).user.id,'usr_legacy');await expect('/projects/prj_solar/access',{cookie:invitedCookie},200);assert.equal(db.prepare('SELECT claimed_uid FROM edgeai_email_approvals WHERE user_id=?').get('usr_legacy').claimed_uid,'uid-invited');});
await check('second UID cannot reuse approval even with same verified email',async()=>expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-other',{email:'invited@example.invalid',email_verified:true})}},403));
await check('duplicate email approval cannot replace identity',()=>expect('/admin/users',{method:'POST',cookie:adminCookie,body:{email:'invited@example.invalid',existing_user_id:'usr_legacy'}},409));
let newUser;
await check('new email approval creates user without granting any project',async()=>{const r=await expect('/admin/users',{method:'POST',cookie:adminCookie,body:{email:'new@example.invalid',full_name:'New Fixture'}},201);newUser=(await r.json()).user_id;assert.equal(db.prepare('SELECT count(*) n FROM project_members WHERE user_id=?').get(newUser).n,0);});
await check('project grant and removal enforce immediate authorization',async()=>{for(const [role,expected] of [[null,403],['editor',200]]){await expect('/admin/users/usr_legacy/projects',{method:'PATCH',cookie:adminCookie,body:{project_id:'prj_solar',role}},200);await expect('/projects/prj_solar/access',{cookie:invitedCookie},expected);}});
await check('administrator protected from accidental self lockout',async()=>{for(const action of ['status','approval','projects'])await expect('/admin/users/usr_frederico/'+action,{method:'PATCH',cookie:adminCookie,body:{is_active:false,revoke:true,project_id:'prj_solar',role:null}},409);});
await check('suspension revokes sessions and reactivation does not revive cookie',async()=>{for(const is_active of [false,true]){await expect('/admin/users/usr_legacy/status',{method:'PATCH',cookie:adminCookie,body:{is_active}},200);await expect('/projects',{cookie:invitedCookie},401);}});
await check('revoked identity cannot reclaim its email approval',async()=>{await expect('/admin/users/usr_legacy/approval',{method:'PATCH',cookie:adminCookie,body:{revoke:true}},200);await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-invited',{email:'invited@example.invalid',email_verified:true})}},403);await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-replacement',{email:'invited@example.invalid',email_verified:true})}},403);});
await check('invalid admin values and missing targets rejected',async()=>{await expect('/admin/users/'+newUser+'/projects',{method:'PATCH',cookie:adminCookie,body:{project_id:'prj_solar',role:'admin'}},400);await expect('/admin/users/usr_missing/status',{method:'PATCH',cookie:adminCookie,body:{is_active:false}},404);});
let freshCookie,freshId;
await check('verified newcomer with forged administrator fields receives isolated user',async()=>{
  const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-fresh',{name:'Administrator'}),user_id:'usr_frederico',is_admin:true,project_id:'prj_solar'}},200);
  freshCookie=cookiePair(r);freshId=(await r.json()).user.id;
  assert.notEqual(freshId,'usr_frederico');assert.equal(db.prepare('SELECT count(*) n FROM project_members WHERE user_id=?').get(freshId).n,0);
  assert.deepEqual((await (await expect('/projects',{cookie:freshCookie},200)).json()).projects,[]);
  await expect('/admin/access',{cookie:freshCookie},403);
  for(const route of ['access','conversations','files','members'])await expect('/projects/prj_solar/'+route,{cookie:freshCookie},403);
});
await check('newcomer personal chat persists and remains invisible to another user',async()=>{
  await expect('/chat',{method:'POST',cookie:freshCookie,body:{message:'Personal test',mode:'personal',conversation_id:'fresh_private'}},200);
  await expect('/me/conversations/fresh_private/messages',{cookie:freshCookie},200);
  await expect('/me/conversations/fresh_private/messages',{cookie:ordinaryCookie},404);
  await expect('/chat',{method:'POST',cookie:ordinaryCookie,body:{message:'steal',conversation_id:'fresh_private'}},403);
});
let personalFile;
await check('personal R2 bytes roundtrip, list and download isolated from other users',async()=>{
  const form=new FormData();form.append('file',new File(['EDGEAI-PRIVATE-BYTES'],'private.txt',{type:'text/plain'}));
  const r=await expect('/me/files',{method:'POST',cookie:freshCookie,raw:form},201);personalFile=(await r.json()).id;
  const downloaded=await expect('/me/files/'+personalFile+'/download',{cookie:freshCookie},200);assert.equal(await downloaded.text(),'EDGEAI-PRIVATE-BYTES');
  assert.equal((await (await expect('/me/files',{cookie:ordinaryCookie},200)).json()).files.length,0);
  await expect('/me/files/'+personalFile+'/download',{cookie:ordinaryCookie},404);
  await expect('/me/files/'+personalFile,{method:'DELETE',cookie:ordinaryCookie},404);
  await expect('/me/files/'+personalFile+'/download',{},401);
});
await check('known UID must still present verified unchanged email',async()=>{
  await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-fresh',{email_verified:false})}},403);
  await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-fresh',{email:'replacement@example.invalid'})}},403);
  await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-impostor',{email:'uid-fresh@example.invalid'})}},403);
});
await check('concurrent exchanges create one identity and no orphan user',async()=>{
  const before=db.prepare('SELECT count(*) n FROM users').get().n;
  const idToken=await token('uid-race',{name:'Administrator'});
  const results=await Promise.all(Array.from({length:8},()=>req('/auth/firebase',{method:'POST',body:{idToken}})));
  const ids=[];for(const r of results){assert.equal(r.status,200,await r.clone().text());ids.push((await r.json()).user.id);}
  assert.equal(new Set(ids).size,1);assert.equal(db.prepare('SELECT count(*) n FROM users').get().n,before+1);
});
await check('concurrent distinct UIDs cannot share one verified email',async()=>{
  const before=db.prepare('SELECT count(*) n FROM users').get().n;
  const tokens=await Promise.all(['uid-contend-a','uid-contend-b'].map(uid=>token(uid,{email:'contended@example.invalid'})));
  const results=await Promise.all(tokens.map(idToken=>req('/auth/firebase',{method:'POST',body:{idToken}})));
  assert.deepEqual(results.map(r=>r.status).sort(),[200,403]);assert.equal(db.prepare('SELECT count(*) n FROM users').get().n,before+1);
});
await check('same display name does not collide with normalized_name or adopt old data',async()=>{
  const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-same-name',{name:'Administrator'})}},200);
  assert.notEqual((await r.json()).user.id,freshId);
});
await check('failed provisioning rolls back all records',async()=>{
  db.exec("CREATE TRIGGER fail_fixture BEFORE INSERT ON edgeai_identity_emails WHEN NEW.email='uid-fail@example.invalid' BEGIN SELECT RAISE(ABORT,'fixture'); END;");
  const before=db.prepare('SELECT count(*) n FROM users').get().n;
  await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-fail')}},500);
  assert.equal(db.prepare('SELECT count(*) n FROM users').get().n,before);
  assert.equal(db.prepare("SELECT count(*) n FROM edgeai_firebase_identities WHERE firebase_uid='uid-fail'").get().n,0);db.exec('DROP TRIGGER fail_fixture');
});
await check('suspended newcomer cannot re-register using same or new UID',async()=>{
  await expect('/admin/users/'+freshId+'/status',{method:'PATCH',cookie:adminCookie,body:{is_active:false}},200);
  await expect('/me/files/'+personalFile+'/download',{cookie:freshCookie},401);
  for(const uid of ['uid-fresh','uid-suspended-bypass'])await expect('/auth/firebase',{method:'POST',body:{idToken:await token(uid,{email:'uid-fresh@example.invalid'})}},403);
  await expect('/admin/users/'+freshId+'/status',{method:'PATCH',cookie:adminCookie,body:{is_active:true}},200);
});
await check('revoked auto identity and old email remain permanently reserved',async()=>{
  await expect('/admin/users/'+freshId+'/approval',{method:'PATCH',cookie:adminCookie,body:{revoke:true}},200);
  for(const [uid,email] of [['uid-fresh','changed@example.invalid'],['uid-reused','uid-fresh@example.invalid']])await expect('/auth/firebase',{method:'POST',body:{idToken:await token(uid,{email})}},403);
});
let managedId;
await check('owner manages editors only inside owned project and sees no global directory',async()=>{
  const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-managed')}},200);managedId=(await r.json()).user.id;
  db.exec("INSERT INTO projects VALUES('prj_other','Other');");
  await expect('/projects/prj_other/members',{cookie:ordinaryCookie},403);
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,body:{user_id:managedId,role:'editor',project_id:'prj_other'}},200);
  assert.equal(db.prepare('SELECT count(*) n FROM project_members WHERE user_id=?').get(managedId).n,1);
  assert.equal(db.prepare('SELECT project_id FROM project_members WHERE user_id=?').get(managedId).project_id,'prj_solar');
  const data=await (await expect('/projects/prj_solar/members',{cookie:ordinaryCookie},200)).json();
  assert(data.members.every(m=>!('email'in m)&&!('firebase_uid'in m)));
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,body:{user_id:managedId,role:'owner'}},400);
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,origin:'https://evil.invalid',body:{user_id:managedId,role:null}},403);
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,body:{user_id:managedId,role:null}},200);
});
await check('global admin sets owner but a different owner cannot remove it',async()=>{
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:adminCookie,body:{user_id:managedId,role:'owner'}},200);
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,body:{user_id:managedId,role:null}},409);
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:adminCookie,body:{user_id:managedId,role:null}},200);
});
await check('owner authority is rechecked during write after concurrent revocation',async()=>{
  const original=DB.batch;
  DB.batch=async function(sts){db.exec("UPDATE project_members SET role='editor' WHERE user_id='owner'");DB.batch=original;return original.call(DB,sts);};
  await expect('/projects/prj_solar/members',{method:'PATCH',cookie:ordinaryCookie,body:{user_id:managedId,role:'editor'}},409);
  await expect('/projects/prj_solar/members',{cookie:ordinaryCookie},403);
  assert.equal(db.prepare('SELECT count(*) n FROM project_members WHERE user_id=?').get(managedId).n,0);
});
await check('pending approval remains reserved while user suspended',async()=>{
  await expect('/admin/users/'+newUser+'/status',{method:'PATCH',cookie:adminCookie,body:{is_active:false}},200);
  await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-pending',{email:'new@example.invalid'})}},403);
});
await check('all foreign keys valid and all auto users have identity and email',async()=>{
  assert.equal(db.prepare('PRAGMA foreign_key_check').all().length,0);
  assert.equal(db.prepare("SELECT count(*) n FROM users u WHERE id LIKE 'usr_%' AND normalized_name LIKE 'firebase-%' AND NOT EXISTS(SELECT 1 FROM edgeai_firebase_identities i WHERE i.user_id=u.id) AND NOT EXISTS(SELECT 1 FROM edgeai_email_approvals a WHERE a.user_id=u.id)").get().n,0);
});
let liveCookie,liveId;
const liveNow=Math.floor(Date.now()/1000);
await check('live session uses two secure host cookies and stores no Firebase token',async()=>{
 const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-live')}},200);
 liveCookie=cookiePair(r);liveId=(await r.json()).user.id;
 const cookies=r.headers.getSetCookie();assert.equal(cookies.length,2);
 assert(cookies.every(c=>/HttpOnly; Secure; SameSite=Lax; Path=\//.test(c)));
 assert(cookies.some(c=>c.startsWith('__Host-edgeai_firebase=')&&!c.includes('Domain=')));
 assert(!JSON.stringify(db.prepare('SELECT * FROM user_sessions').all()).includes(liveCookie.split('__Host-edgeai_firebase=')[1]));
});
await check('each request does a fresh lookup, only duplicate checks within one request are reused',async()=>{
 const before=liveCalls;await expect('/projects',{cookie:liveCookie},200);assert.equal(liveCalls,before+1);
 await expect('/projects',{cookie:liveCookie},200);assert.equal(liveCalls,before+2);
});
await check('Firebase cookie cannot be removed or replaced with another account token',async()=>{
 const primary=liveCookie.split('; ')[0];await expect('/projects',{cookie:primary},401);
 await expect('/projects',{cookie:primary+'; __Host-edgeai_firebase='+await token('uid-admin')},401);
});
await check('Firebase suspension denies an existing session on its very next request',async()=>{
 firebaseAccounts.set('uid-live',{disabled:true});
 const before=providerCalls;const r=await expect('/auth/session',{cookie:liveCookie},200);assert.equal((await r.json()).authenticated,false);
 for(const path of ['/projects','/me/conversations','/me/files','/projects/prj_solar/files','/upload','/chat'])await expect(path,{cookie:liveCookie,method:['/upload','/chat'].includes(path)?'POST':'GET',body:path==='/chat'?{message:'must not run'}:undefined},401);
 assert.equal(providerCalls,before);
 firebaseAccounts.delete('uid-live');await expect('/projects',{cookie:liveCookie},401);
});
await check('revocation uses auth_time even if iat is newer and signed token has not expired',async()=>{
 firebaseAccounts.set('uid-live',{validSince:String(liveNow-100)});
 await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-live',{auth_time:liveNow-500,iat:liveNow-5})}},401);
});
await check('fresh reauthentication after revocation preserves D1 identity and membership',async()=>{
 const before=db.prepare('SELECT count(*) n FROM users').get().n;
 const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-live',{auth_time:liveNow-1,iat:liveNow})}},200);
 assert.equal((await r.json()).user.id,liveId);liveCookie=cookiePair(r);
 assert.equal(db.prepare('SELECT count(*) n FROM users').get().n,before);assert.equal(db.prepare('SELECT count(*) n FROM project_members WHERE user_id=?').get(liveId).n,0);
});
for(const mode of ['network','outage','bad-key','malformed'])await check('Firebase '+mode+' fails closed without revoking valid D1 records',async()=>{
 const before=db.prepare('SELECT count(*) n FROM user_sessions WHERE revoked_at IS NOT NULL').get().n,providers=providerCalls;
 firebaseLookupMode=mode;
 await expect('/auth/session',{cookie:liveCookie},503);await expect('/projects',{cookie:liveCookie},503);
 await expect('/chat',{cookie:liveCookie,method:'POST',body:{message:'must not reach AI'}},503);
 assert.equal(providerCalls,providers);assert.equal(db.prepare('SELECT count(*) n FROM user_sessions WHERE revoked_at IS NOT NULL').get().n,before);
 firebaseLookupMode='ok';await expect('/projects',{cookie:liveCookie},200);
});
await check('Firebase response with missing revocation metadata is not trusted',async()=>{
 firebaseAccounts.set('uid-live',{validSince:undefined});await expect('/projects',{cookie:liveCookie},503);
 firebaseAccounts.set('uid-live',{disabled:'false'});await expect('/projects',{cookie:liveCookie},503);
 firebaseAccounts.delete('uid-live');
});
await check('a changed account creation timestamp cannot reuse an old UID to reach D1 data',async()=>{
 firebaseAccounts.set('uid-live',{createdAt:String((liveNow-10)*1000)});
 await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-live',{auth_time:liveNow-1,iat:liveNow})}},403);
 assert.equal(db.prepare('SELECT created_at_ms FROM edgeai_firebase_account_origins WHERE firebase_uid=?').get('uid-live').created_at_ms,fixtureCreatedAt);
 firebaseAccounts.delete('uid-live');
});
await check('Firebase revocation invalidates a valid backend cookie before its expiry',async()=>{
 firebaseAccounts.set('uid-live',{validSince:String(liveNow+1)});
 await expect('/projects',{cookie:liveCookie},401);
 firebaseAccounts.delete('uid-live');await expect('/projects',{cookie:liveCookie},401);
});
for(const error of ['USER_DISABLED','USER_NOT_FOUND','INVALID_ID_TOKEN','TOKEN_EXPIRED'])await check('Firebase '+error+' cannot create a replacement user',async()=>{
 const before=db.prepare('SELECT count(*) n FROM users').get().n;
 firebaseAccounts.set('uid-provider-denied',{error});
 await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-provider-denied')}},401);
 assert.equal(db.prepare('SELECT count(*) n FROM users').get().n,before);
});
await check('revocation during a long AI call suppresses private response and assistant persistence',async()=>{
 const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-during')}},200),cookie=cookiePair(r);
 beforeModelReturn=async()=>firebaseAccounts.set('uid-during',{disabled:true});
 const result=await expect('/chat',{method:'POST',cookie,body:{message:'fixture',mode:'personal',conversation_id:'revoked_during_model'}},401);
 assert(!((await result.text()).includes('Fixture answer')));
 assert.equal(db.prepare("SELECT count(*) n FROM messages WHERE conversation_id='revoked_during_model' AND role='assistant'").get().n,0);
 beforeModelReturn=null;
});
await check('Firebase outage during a long AI call also suppresses private response',async()=>{
 const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-during-outage')}},200),cookie=cookiePair(r);
 beforeModelReturn=async()=>{firebaseLookupMode='outage';};
 await expect('/chat',{method:'POST',cookie,body:{message:'fixture',mode:'personal',conversation_id:'outage_during_model'}},503);
 assert.equal(db.prepare("SELECT count(*) n FROM messages WHERE conversation_id='outage_during_model' AND role='assistant'").get().n,0);
 beforeModelReturn=null;firebaseLookupMode='ok';
});
await check('logout expires both cookies and does not require a functioning Firebase provider',async()=>{
 const r=await expect('/auth/firebase',{method:'POST',body:{idToken:await token('uid-logout-live')}},200),cookie=cookiePair(r);
 firebaseLookupMode='outage';const out=await expect('/auth/logout',{cookie,method:'POST'},200);
 assert.equal(out.headers.getSetCookie().length,2);assert(out.headers.getSetCookie().every(c=>c.includes('Max-Age=0')));
 firebaseLookupMode='ok';await expect('/projects',{cookie},401);
});
await check('live-state migration leaves all foreign keys valid',async()=>assert.deepEqual(db.prepare('PRAGMA foreign_key_check').all(),[]));
assert.equal(keyCalls,1);console.log(JSON.stringify({passed,keyCacheVerified:true,providerCalls,liveCalls}));
