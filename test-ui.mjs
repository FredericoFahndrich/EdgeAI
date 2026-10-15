import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync('index.html','utf8');
for(const m of html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)) {
  if(!m[1].includes('type="module"'))new vm.Script(m[2]);
}
const code=html.slice(html.indexOf('// Chat authorization is granted'),html.indexOf('function setupEdgeaiLoginForm()'));
const nodes=new Map();const node=id=>{if(!nodes.has(id))nodes.set(id,{hidden:false,value:'secret',textContent:'private',children:[],replaceChildren(){this.textContent='';},setAttribute(){},removeAttribute(){}});return nodes.get(id);};
const screen=node('edgeaiLoginScreen');const shell=node('shell');screen.parentElement={children:[screen]};
let revokeFails=false,deny=false,session=null,providerUser='owner',signedOut=false,hold,release;
const sandbox={console,crypto,Date,Promise,document:{body:{children:[screen.parentElement,shell]},getElementById:node},window:{edgeaiFirebaseStatus:{},edgeaiFirebase:{auth:{}}},BACKEND_URL:'https://edgeai.test',isWorkerOrigin:true,
render(){},refreshSelectedFiles(){},updateAuthControls(){},updateWorkspaceOptions(){},
async loadUserProjects(){},async switchWorkspace(){},
async fetch(url,options){
 if(url.endsWith('/auth/logout')) {if(revokeFails)return {ok:false};session=null;return {ok:true};}
 if(url.endsWith('/auth/firebase')) {if(hold)await hold;if(deny)return {ok:false,json:async()=>({error:'identity_not_approved'})};session={id:providerUser};return {ok:true,json:async()=>({user:session,expires_at:new Date(Date.now()+3600000).toISOString()})};}
 if(url.endsWith('/auth/session')) return {ok:true,json:async()=>({authenticated:!!session,user:session})};
 return {status:401};
}};
const c=vm.createContext(sandbox);
vm.runInContext(`let contentEpoch=0,authUser=null,availableProjects=[],messages=[],apiHistory=[],conversationId='',currentScope='',hasMoreMessages=false,nextBeforeMessage=null;`,c);
vm.runInContext(code,c);
vm.runInContext('firebaseSdk={async signOut(){window.didSignOut=true;}};',c);
let passed=0;const check=async(name,fn)=>{await fn();passed++;console.log('PASS '+name);};
const user={getIdToken:async()=>'fixture-token'};
await check('unapproved Firebase user keeps UI locked',async()=>{deny=true;await c.syncFirebaseUser(user);assert.equal(screen.hidden,false);assert.equal(sandbox.window.edgeaiFirebaseStatus.backendIntegrated,false);});
await check('verified session unlocks UI',async()=>{deny=false;await c.syncFirebaseUser(user);assert.equal(screen.hidden,true);assert.equal(vm.runInContext('authUser.id',c),'owner');});
await check('logout wipes cached private state and revokes server session',async()=>{vm.runInContext('messages=[{content:"secret"}];',c);await c.logoutUser();assert.equal(session,null);assert.equal(screen.hidden,false);assert.equal(vm.runInContext('messages.length',c),0);assert.equal(node('projectFilesList').textContent,'');assert.equal(sandbox.window.didSignOut,true);});
await check('failed revocation never reports successful signout',async()=>{sandbox.window.didSignOut=false;revokeFails=true;await c.logoutUser();assert.equal(sandbox.window.didSignOut,false);assert.match(node('edgeaiLoginStatus').textContent,/revogar/);assert.equal(screen.hidden,false);revokeFails=false;});
await check('account switch discards stale exchange before UI unlock',async()=>{hold=new Promise(r=>release=r);const first=c.syncFirebaseUser(user);await new Promise(r=>setImmediate(r));const second=c.syncFirebaseUser(null);hold=null;release();await Promise.all([first,second]);assert.equal(screen.hidden,false);assert.equal(session,null);assert.equal(vm.runInContext('authUser',c),null);});
await check('HTTP 401 invalidates generation and locks chat',async()=>{await c.syncFirebaseUser(user);const generation=vm.runInContext('authGeneration',c);await c.edgeaiFetch('https://edgeai.test/chat',{});assert.equal(screen.hidden,false);assert(vm.runInContext('authGeneration',c)>generation);});
console.log(JSON.stringify({passed,scriptSyntax:true,scope:'DOM stubs and mocked HTTP; no real account/browser proof'}));
