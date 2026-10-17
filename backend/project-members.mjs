export async function handleProjectMembers(request,env,url,{authenticate,reply,readJson}) {
  const match=url.pathname.match(/^\/projects\/([A-Za-z0-9_-]{3,100})\/members$/);
  if(!match)return null;
  const actor=await authenticate(request,env);
  if(!actor)return reply(request,{error:'Autenticação necessária.'},401);
  const project=match[1],admin=actor.id==='usr_frederico';
  const owns=await env.DB.prepare("SELECT 1 AS ok FROM project_members WHERE project_id=?1 AND user_id=?2 AND role='owner'").bind(project,actor.id).first();
  if(!admin&&!owns)return reply(request,{error:'Gerenciamento de membros não autorizado.'},403);
  if((request.method!=='GET'||request.headers.has('Origin'))&&request.headers.get('Origin')!==url.origin)return reply(request,{error:'Origem não autorizada.'},403);
  if(!await env.DB.prepare('SELECT id FROM projects WHERE id=?1').bind(project).first())return reply(request,{error:'Projeto não encontrado.'},404);
  if(request.method==='GET') {
    const members=await env.DB.prepare(`SELECT u.id,u.full_name,pm.role FROM project_members pm JOIN users u ON u.id=pm.user_id WHERE pm.project_id=?1 ORDER BY u.full_name`).bind(project).all();
    return reply(request,{members:members.results});
  }
  if(request.method!=='PATCH')return reply(request,{error:'Método não permitido.'},405);
  if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type')||''))return reply(request,{error:'Use application/json.'},415);
  let body;try{body=await readJson(request);}catch{return reply(request,{error:'JSON inválido.'},400);}
  if(!body||typeof body.user_id!=='string'||!/^usr_[a-zA-Z0-9_-]{1,100}$/.test(body.user_id)||!['editor',null,...(admin?['owner']:[])].includes(body.role))return reply(request,{error:'Usuário ou papel inválido. Proprietários gerenciam editores; administradores definem proprietários.'},400);
  if(body.user_id===actor.id||body.user_id==='usr_frederico')return reply(request,{error:'Este vínculo está protegido.'},409);
  // Revalidate owner authority AND current target role within the write transaction.
  const guard=`EXISTS(SELECT 1 FROM users WHERE id=?4 AND is_active=1)
    AND (?5=1 OR EXISTS(SELECT 1 FROM project_members WHERE project_id=?1 AND user_id=?4 AND role='owner'))
    AND (?5=1 OR NOT EXISTS(SELECT 1 FROM project_members WHERE project_id=?1 AND user_id=?2 AND role='owner'))
    AND EXISTS(SELECT 1 FROM users WHERE id=?2 AND is_active=1)`;
  const statement=body.role===null
    ? env.DB.prepare(`DELETE FROM project_members WHERE project_id=?1 AND user_id=?2 AND ?3 IS NULL AND ${guard}`)
    : env.DB.prepare(`INSERT INTO project_members(project_id,user_id,role) SELECT ?1,?2,?3 WHERE ${guard}
        ON CONFLICT(project_id,user_id) DO UPDATE SET role=excluded.role`);
  const results=await env.DB.batch([
    statement.bind(project,body.user_id,body.role,actor.id,admin?1:0),
    env.DB.prepare(`INSERT INTO edgeai_admin_audit(id,actor_user_id,action,target_user_id,detail,created_at)
      SELECT ?1,?2,'project_access',?3,?4,?5 WHERE changes()>0`)
      .bind(crypto.randomUUID(),actor.id,body.user_id,JSON.stringify({project_id:project,role:body.role}),new Date().toISOString())
  ]);
  return results[0].meta.changes ? reply(request,{updated:true}) : reply(request,{error:'Vínculo não alterado: usuário indisponível ou permissão insuficiente.'},409);
}
