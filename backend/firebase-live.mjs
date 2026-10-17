// This is the existing public Firebase Web API key, not an Admin credential.
const WEB_API_KEY = 'AIzaSyCTgHxl5LzEV1bCqDJSU14cElGDZi3xonU';
const LOOKUP_URL = 'https://identitytoolkit.googleapis.com/v1/accounts:lookup?key='+WEB_API_KEY;
export class FirebaseStatusUnavailable extends Error {
  constructor() {super('Firebase status unavailable');this.code='firebase_status_unavailable';}
}
// No cross-request positive cache: every protected request observes Firebase's current state.
export async function lookupFirebaseAccount(idToken,claims) {
  let response,data;
  try {
    response=await fetch(LOOKUP_URL,{
      method:'POST',headers:{'Content-Type':'application/json','Cache-Control':'no-store'},
      body:JSON.stringify({idToken}),signal:AbortSignal.timeout(8000),redirect:'manual'
    });
    data=await response.json();
  } catch {throw new FirebaseStatusUnavailable();}
  if(!response.ok){
    const code=data?.error?.message?.split(' : ')[0];
    if(response.status===400 && ['USER_DISABLED','USER_NOT_FOUND','INVALID_ID_TOKEN','TOKEN_EXPIRED','CREDENTIAL_TOO_OLD_LOGIN_AGAIN'].includes(code))return null;
    throw new FirebaseStatusUnavailable();
  }
  if(!Array.isArray(data.users)||data.users.length!==1) {
    if(Array.isArray(data.users)&&data.users.length===0)return null;
    throw new FirebaseStatusUnavailable();
  }
  const user=data.users[0];
  if(user.disabled!==undefined && typeof user.disabled!=='boolean')throw new FirebaseStatusUnavailable();
  if(typeof user.validSince!=='string'||!/^\d{1,16}$/.test(user.validSince)||!Number.isSafeInteger(Number(user.validSince)) ||
    typeof user.createdAt!=='string'||!/^\d{1,16}$/.test(user.createdAt)||!Number.isSafeInteger(Number(user.createdAt)))throw new FirebaseStatusUnavailable();
  // auth_time, rather than iat, preserves revocation across silent token refresh.
  if(user.localId!==claims.sub || user.disabled===true || user.emailVerified!==true ||
    typeof user.email!=='string' || typeof claims.email!=='string' || user.email.trim().toLowerCase()!==claims.email.trim().toLowerCase() ||
    claims.email_verified!==true || claims.auth_time<Number(user.validSince) ||
    Math.floor(Number(user.createdAt)/1000)>claims.auth_time)return null;
  return {createdAt:user.createdAt};
}
export function sessionCookies(request) {
  const cookie=request.headers.get('Cookie')||'';
  const session=cookie.match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/)?.[1];
  const firebase=cookie.match(/(?:^|;\s*)__Host-edgeai_firebase=([A-Za-z0-9_.-]{1,3800})(?:;|$)/)?.[1];
  return {session,firebase};
}
export async function sessionHash(session,firebase,digest) {
  return digest(firebase?'firebase-live-v1:'+session+':'+firebase:session);
}
