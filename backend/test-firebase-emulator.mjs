import assert from 'node:assert/strict';
import {lookupFirebaseAccount} from './firebase-live.mjs';
const emulator=process.env.FIREBASE_AUTH_EMULATOR_HOST;
assert.equal(emulator,'127.0.0.1:9099','This test is restricted to the local emulator');
const realFetch=globalThis.fetch,root='http://'+emulator+'/identitytoolkit.googleapis.com/v1/';
async function api(path,body,admin=false){
 const r=await realFetch(root+path+'?key=emulator-fixture',{method:'POST',headers:{'Content-Type':'application/json',...(admin?{Authorization:'Bearer owner'}:{})},body:JSON.stringify(body)});
 const data=await r.json();assert(r.ok,JSON.stringify({status:r.status,code:data.error?.message}));return data;
}
globalThis.fetch=(url,options)=>{
 assert(String(url).startsWith('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key='));
 return realFetch(root+'accounts:lookup?key=emulator-fixture',options);
};
const email='emulator-only@example.invalid',password='Local-fixture-'+crypto.randomUUID();
const created=await api('accounts:signUp',{email,password,returnSecureToken:true});
await api('accounts:update',{localId:created.localId,emailVerified:true},true);
const login=await api('accounts:signInWithPassword',{email,password,returnSecureToken:true});
const claims=JSON.parse(Buffer.from(login.idToken.split('.')[1],'base64url').toString());
const original=await lookupFirebaseAccount(login.idToken,claims);assert(original);
console.log('PASS emulator: verified account lookup');
await api('accounts:update',{localId:created.localId,disableUser:true},true);
assert.equal(await lookupFirebaseAccount(login.idToken,claims),null);
console.log('PASS emulator: disabled account invalidates the existing token');
await api('accounts:update',{localId:created.localId,disableUser:false},true);
await api('accounts:update',{localId:created.localId,validSince:String(claims.auth_time+1)},true);
assert.equal(await lookupFirebaseAccount(login.idToken,claims),null);
console.log('PASS emulator: revocation timestamp invalidates the existing unexpired token');
await api('accounts:delete',{localId:created.localId},true);
assert.equal(await lookupFirebaseAccount(login.idToken,claims),null);
console.log('PASS emulator: deleted account invalidates the existing token');
globalThis.fetch=realFetch;
console.log(JSON.stringify({passed:4,emulatorOnly:true,productionAccountsTouched:false}));
