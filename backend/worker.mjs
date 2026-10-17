import {resolveVerifiedIdentity} from './identity-registration.mjs';
import {handleProjectMembers} from './project-members.mjs';
/**
 * ============================================================================
 * EDGE AI — BACKEND 3.0.0
 * ============================================================================
 * Plataforma : EDGE AI Web Page
 * Ambiente   : Cloudflare Workers (ES Modules)
 * Armazenam. : Cloudflare D1 (DB) e Cloudflare R2 (FILES_BUCKET)
 * Integrações: Firebase Authentication, OpenAI, Resend e Slack
 * Frontend   : Aplicação servida em /app; recursos do GitHub Pages
 *
 * SEGURANÇA
 * - A identidade é validada no Worker: JWT Firebase RS256 + vínculo D1.
 * - A autorização dos projetos depende de project_members, não do nome.
 * - Sessões são armazenadas com hash e exigem cookie HttpOnly/Secure.
 * - A administração requer o ID D1 previamente autorizado.
 * - Nunca registrar tokens de autenticação, cookies ou segredos em logs.
 *
 * COMPATIBILIDADE
 * - Preserva contratos HTTP, SQL, políticas de acesso e lógica da versão
 *   fornecida, incluindo a correção JWKS (redirect: 'manual').
 * - Organização de código e documentação não equivalem a teste em produção.
 * - Revalidar login, sessão, permissões, chat e uploads antes do corte final.
 *
 * Este arquivo é independente: editar/publicar manualmente no Cloudflare.
 * ============================================================================
 */
/* ============================================================================
 * 01 — CONSTANTES DE CONFIGURAÇÃO
 * Identidades, chaves públicas, limites e políticas de origem.
 * ========================================================================== */
const EDGEAI_ADMIN_USER_ID = 'usr_frederico';
const FIREBASE_PROJECT = 'edgeai-auth';
const FIREBASE_JWKS = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let firebaseKeyCache = { until: 0, keys: [] };
let firebaseKeyRequest;
const BACKEND_VERSION = "3.0.1";
const DEFAULT_MODEL = "gpt-5";
const MAX_HISTORY_MESSAGES = 20;
const ALLOWED_ORIGINS = [
  "https://fredericofahndrich.github.io",
  "https://edgeai-backend.frederico-fahndrich.workers.dev",
  "http://localhost:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
];
const PROJECT_DOCUMENT_LIMIT = 15 * 1024 * 1024;
const PROJECT_DOCUMENT_TYPES = {
  pdf: "application/pdf",
  txt: "text/plain",
  md: "text/markdown",
  csv: "text/csv",
  json: "application/json",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
};
/* ============================================================================
 * 02 — INSTRUÇÕES DO MODELO E CONTRATO DE RESPOSTA
 * Prompt base e esquema JSON exigido para a API OpenAI.
 * ========================================================================== */
const BASE_INSTRUCTIONS = `
Você é uma IA de borda especializada em engenharia,
sistemas embarcados, eletrônica, hardware ARM,
Raspberry Pi e inteligência artificial.

Você foi criada por Frederico Fähndrich.

Responda de maneira técnica, clara, objetiva e profissional.

Quando perguntarem "quem é você", responda exatamente:
"Sou uma IA de borda criada por Frederico Fähndrich."

Quando o nome do visitante for conhecido,
você poderá utilizá-lo naturalmente quando apropriado.

Se houver PDFs, analise seu conteúdo quando relevante.
Prefira respostas claras, práticas e bem estruturadas.

============================================================
AUTOMAÇÃO DE ALTERAÇÕES NO LINKEDIN
============================================================

Além de responder normalmente ao visitante,
identifique se ele está solicitando uma alteração
no perfil do LinkedIn de Frederico Fähndrich.

Considere como referências à mesma pessoa quando
o contexto for claro:
- Frederico
- Frederico Gama
- Frederico Fähndrich
- Frederico Fahndrich
- perfil do Frederico
- perfil de Frederico
- LinkedIn de Frederico
- LinkedIn do Frederico

Exemplo que DEVE gerar uma ação:
"Modifique o perfil de Frederico Gama no LinkedIn,
no campo Sobre, para: Engenheiro eletrônico com
mais de 10 anos de experiência."

Outros exemplos que DEVEM gerar ação:
"Peça ao Frederico para adicionar isso no LinkedIn."
"Altere a seção Sobre do LinkedIn de Frederico."
"Adicione essa certificação ao perfil de Frederico."
"Remova essa informação do LinkedIn de Frederico."
"Corrija essa experiência profissional no LinkedIn do Frederico."

Quando houver uma solicitação clara:
linkedin_action.required = true
linkedin_action.field deve informar exatamente a seção ou campo que deverá ser alterado.
linkedin_action.instruction deve informar exatamente o que Frederico deverá adicionar, substituir, corrigir, modificar ou remover.

============================================================
NÃO CRIAR AÇÃO SEM NECESSIDADE
============================================================

Não crie uma ação simplesmente porque a palavra LinkedIn apareceu na conversa.

Exemplos que NÃO devem gerar ação:
"Como melhorar meu LinkedIn?"
"Como funciona o LinkedIn?"
"Frederico possui LinkedIn?"
"O que devo colocar na seção Sobre?"
"Qual é a importância do LinkedIn?"

Nesses casos:
linkedin_action.required = false
linkedin_action.field = ""
linkedin_action.instruction = ""

Também não considere automaticamente que "meu LinkedIn" é o perfil de Frederico quando quem está conversando é outra pessoa.
A solicitação precisa estar claramente relacionada ao perfil de Frederico.

============================================================
RESPOSTA VISÍVEL AO VISITANTE
============================================================

A propriedade "message" é a ÚNICA informação mostrada ao visitante.

Nunca mencione em "message":
- linkedin_action
- automação interna
- e-mail
- Resend
- Slack
- banco de dados
- Cloudflare
- JSON
- processamento interno
- que Frederico será notificado

Quando a mensagem do visitante for apenas uma solicitação para modificar o LinkedIn de Frederico, responda de forma curta e natural.

Exemplos:
"Certo."
"Entendido."

Não diga:
"Vou enviar isso ao Frederico."
"Frederico será notificado."
"Vou atualizar o LinkedIn."
"Já alterei o LinkedIn."
`;
const RESPONSE_FORMAT = {
  type: "json_schema",
  name: "edge_ai_response",
  strict: true,
  schema: {
    type: "object",
    properties: {
      message: {
        type: "string"
      },
      linkedin_action: {
        type: "object",
        properties: {
          required: { type: "boolean" },
          field: { type: "string" },
          instruction: { type: "string" }
        },
        required: ["required", "field", "instruction"],
        additionalProperties: false
      }
    },
    required: ["message", "linkedin_action"],
    additionalProperties: false
  }
};
/* ============================================================================
 * 03 — UTILITÁRIOS E VALIDAÇÃO DE REQUISIÇÕES
 * Normalização, CORS, corpos HTTP, hashing e nomes de arquivos.
 * ========================================================================== */
/** Normaliza um e-mail para busca no cadastro de aprovações. A normalização, isoladamente, não autoriza ninguém. */
function normalizedApprovalEmail(value) {
  if (typeof value !== 'string' || value.length > 254)
    return null;
  const email = value.trim().toLowerCase();
  return /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$/.test(email) ? email : null;
}
/** Determina se Origin é aceito para CORS. CORS não substitui autenticação nem checagem de permissões. */
function isAllowedOrigin(origin) {
  if (!origin)
    return true;
  return ALLOWED_ORIGINS.includes(origin);
}
/** Monta cabeçalhos CORS para origens permitidas e credenciais de sessão. */
function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = origin && ALLOWED_ORIGINS.includes(origin) ? origin : null;
  return {
    ...(allowedOrigin ? { "Access-Control-Allow-Origin": allowedOrigin, "Access-Control-Allow-Credentials": "true" } : {}),
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-EdgeAI-Guest",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
/** Centraliza respostas JSON com políticas de cache e cabeçalhos básicos de segurança. */
function jsonResponse(request, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
      ...getCorsHeaders(request)
    }
  });
}
/** Valida IDs de conversas antes de compor consultas e rotas. */
function normalizeConversationId(value) {
  if (typeof value !== "string")
    return "";
  const id = value.trim();
  if (id.length < 5 || id.length > 100)
    return "";
  if (!/^[a-zA-Z0-9_-]+$/.test(id))
    return "";
  return id;
}
/** Trata o nome apenas como dado de apresentação, nunca como prova de identidade. */
function normalizeUserName(value) {
  if (typeof value !== "string")
    return "Visitante";
  let name = value.trim();
  if (!name)
    return "Visitante";
  if (name.length > 80)
    name = name.substring(0, 80);
  return name;
}
/** Valida a sintaxe do ID de projeto; permissão é verificada separadamente em project_members. */
function validatedProjectId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{3,100}$/.test(value) ? value : null;
}
/** Limita títulos de conversas e usa um título padrão quando necessário. */
function cleanTitle(value, fallback = "Nova conversa") {
  const s = typeof value === "string" ? value.trim().replace(/\s+/g, " ") : "";
  return (s || fallback).slice(0, 120);
}
/** Lê corpos HTTP em streaming com limite explícito para evitar cargas excessivas. */
async function readBoundedBody(request, limit) {
  const reader = request.body?.getReader();
  if (!reader)
    return new Uint8Array();
  const chunks = [];
  let size = 0;
  for (; ;) {
    const { done, value } = await reader.read();
    if (done)
      break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new Error("Requisição excede o limite de tamanho.");
    }
    chunks.push(value);
  }
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}
/** Decodifica JSON de requisições com limite de 128 KiB. */
async function readJsonBounded(request) {
  return JSON.parse(new TextDecoder().decode(await readBoundedBody(request, 131072)));
}
/** Lê JSON com limite de tamanho; retorna null para corpo ausente ou inválido. */
async function readOptionalJson(request) {
  try {
    const body = await readJsonBounded(request);
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  }
  catch {
    return null;
  }
}
/** Decodifica multipart com limite total de aproximadamente 15 MiB. */
async function readMultipartBounded(request) {
  return new Response(await readBoundedBody(request, 15 * 1024 * 1024 + 65536), {
    headers: { "Content-Type": request.headers.get("Content-Type") || "" }
  }).formData();
}
/** Calcula SHA-256 usado para armazenar identificadores de sessão e controles sem gravar o valor original. */
async function digestKey(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, "0")).join("");
}
/** Escapa conteúdo inserido em e-mails HTML de notificação. */
function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
/** Converte quebras de linha para exibição HTML em mensagens de notificação. */
function nl2br(text) {
  return String(text).replace(/\n/g, "<br>");
}
/** Restringe caracteres de nomes de arquivos antes de salvar metadados. */
function projectFileSafeName(name) {
  return String(name || "arquivo")
    .replace(/[\\/\x00-\x1f\x7f]/g, "_")
    .replace(/[\r\n]/g, " ")
    .trim().slice(0, 180) || "arquivo";
}
/** Gera Content-Disposition compatível com nomes Unicode. */
function projectFileDownloadName(name) {
  const ascii = String(name)
    .normalize("NFKD")
    .replace(/[^\x20-\x7e]/g, "_")
    .replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}
/* ============================================================================
 * 04 — FIREBASE — CHAVES PÚBLICAS E VERIFICAÇÃO JWT
 * Consulta JWKS Google e validação obrigatória RS256 e claims.
 * ========================================================================== */
/** Decodifica um segmento JWT Base64URL e rejeita caracteres fora do alfabeto permitido. */
function decodeFirebasePart(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value))
    throw new Error('Invalid token');
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
/** Consulta chaves públicas JWKS do Google em URL fixa, com cache e tempo limite. IMPORTANTE: redirect: manual é necessário no runtime Cloudflare Workers. */
async function firebaseKeys() {
  if (firebaseKeyCache.until > Date.now()) {
    return firebaseKeyCache.keys;
  }
  if (!firebaseKeyRequest) {
    firebaseKeyRequest = (async () => {
      if (typeof AbortSignal.timeout !== 'function') {
        throw new Error('Key fetch runtime');
      }
      let response;
      try {
        response = await fetch(FIREBASE_JWKS, {
          signal: AbortSignal.timeout(8000),
          redirect: 'manual'
        });
      }
      catch (error) {
        if (error?.name === 'TimeoutError' ||
          error?.name === 'AbortError') {
          throw new Error('Key fetch timeout');
        }
        throw new Error('Key fetch network');
      }
      if (!response.ok) {
        throw new Error('Key fetch HTTP ' + response.status);
      }
      let data;
      try {
        data = await response.json();
      }
      catch {
        throw new Error('Key fetch JSON');
      }
      if (!Array.isArray(data?.keys) || !data.keys.length) {
        throw new Error('Key fetch schema');
      }
      const maxAge = Number((response.headers.get('Cache-Control') || '')
        .match(/max-age=(\d+)/)?.[1] || 300);
      firebaseKeyCache = {
        keys: data.keys,
        until: Date.now() + Math.min(maxAge, 3600) * 1000
      };
      return data.keys;
    })().finally(() => {
      firebaseKeyRequest = null;
    });
  }
  return firebaseKeyRequest;
}
/** Valida issuer, audience, tempos, provedor, algoritmo e assinatura RS256. Qualquer falha impede a emissão da sessão. */
async function verifyFirebaseIdToken(token) {
  if (typeof token !== 'string' || token.length > 16384)
    throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3)
    throw new Error('Invalid token');
  const header = JSON.parse(new TextDecoder().decode(decodeFirebasePart(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeFirebasePart(parts[1])));
  const now = Math.floor(Date.now() / 1000);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length > 256 || header.crit ||
    claims.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT || claims.aud !== FIREBASE_PROJECT ||
    typeof claims.sub !== 'string' || !claims.sub.length || claims.sub.length > 128 ||
    !Number.isInteger(claims.exp) || claims.exp <= now ||
    !Number.isInteger(claims.iat) || claims.iat > now || claims.iat >= claims.exp ||
    !Number.isInteger(claims.auth_time) || claims.auth_time > now || claims.auth_time > claims.iat ||
    claims.firebase?.tenant || !['google.com', 'password'].includes(claims.firebase?.sign_in_provider)) {
    throw new Error('Invalid claims');
  }
  let keys;
  try {
    keys = await firebaseKeys();
  }
  catch (error) {
    const reason = error?.message || '';
    const knownFailure = [
      'Key fetch runtime',
      'Key fetch timeout',
      'Key fetch network',
      'Key fetch JSON',
      'Key fetch schema'
    ].includes(reason);
    if (knownFailure ||
      /^Key fetch HTTP [1-5]\d\d$/.test(reason)) {
      throw error;
    }
    throw new Error('Key service unavailable');
  }
  const jwk = keys.find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk)
    throw new Error('Unknown signing key');
  let key;
  try {
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  }
  catch {
    throw new Error('Key import unavailable');
  }
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, decodeFirebasePart(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]))) {
    throw new Error('Invalid signature');
  }
  return claims;
}
/* ============================================================================
 * 05 — IDENTIDADES FIREBASE E SESSÕES D1
 * Aprovação controlada, troca de token por cookie seguro e revalidação.
 * ========================================================================== */
/** Consome uma aprovação explícita após validar token assinado e email_verified=true. Preserva vínculos existentes ou revogados; não identifica usuários pelo nome. */
/** Troca um ID token Firebase válido por sessão D1 somente para identidade vinculada/aprovada. O cookie expira no máximo junto com o token Firebase. */
async function exchangeFirebaseSession(request, env) {
  if (request.headers.get('Origin') !== new URL(request.url).origin)
    return jsonResponse(request, { error: 'Abra o EDGE AI pelo endereço /app do Worker.' }, 403);
  if (!env.DB)
    return jsonResponse(request, { error: 'Banco indisponível.' }, 503);
  const key = await digestKey('firebase:' + (request.headers.get('CF-Connecting-IP') || 'unknown'));
  const limit = await env.DB.prepare(`INSERT INTO auth_login_limits(client_key,window_minute,attempts)
    VALUES(?1,?2,1) ON CONFLICT(client_key) DO UPDATE SET
    attempts=CASE WHEN window_minute=excluded.window_minute THEN attempts+1 ELSE 1 END,
    window_minute=excluded.window_minute RETURNING attempts`).bind(key, Math.floor(Date.now() / 60000)).first();
  if (limit.attempts > 20)
    return jsonResponse(request, { error: 'Muitas tentativas. Aguarde um minuto.' }, 429);
  let claims;
  try {
    const body = await readJsonBounded(request);
    claims = await verifyFirebaseIdToken(body?.idToken);
  }
  catch (error) {
    const codes = {
      'Invalid claims': 'claims',
      'Key service unavailable': 'key_fetch',
      'Unknown signing key': 'key_missing',
      'Key import unavailable': 'key_import',
      'Invalid signature': 'signature'
    };
    const details = {
      'Key fetch runtime': 'key_runtime',
      'Key fetch timeout': 'key_timeout',
      'Key fetch network': 'key_network',
      'Key fetch JSON': 'key_json',
      'Key fetch schema': 'key_schema'
    };
    const reason = error?.message || '';
    const stage = codes[reason] ||
      details[reason] ||
      (/^Key fetch HTTP [1-5]\d\d$/.test(reason)
        ? 'key_http_' + reason.slice(-3)
        : 'token_format');
    return jsonResponse(request, {
      error: 'Falha na validação Firebase (' + stage + ').',
      code: 'firebase_' + stage
    }, 401);
  }
  const user = await resolveVerifiedIdentity(env, claims, normalizedApprovalEmail);
  if (!user) return jsonResponse(request, {error:'E-mail não verificado ou identidade bloqueada/reservada.',code:'identity_not_approved'},403);
  // A session never outlives the signed ID token. Refresh requires another verified token.
  const token = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const id = crypto.randomUUID(), tokenHash = await digestKey(token);
  const expiresAt = new Date(claims.exp * 1000).toISOString();
  const previous = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/)?.[1];
  const statements = [
    env.DB.prepare('INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?1,?2,?3,?4)').bind(id, user.id, tokenHash, expiresAt),
    env.DB.prepare('INSERT INTO edgeai_firebase_sessions(session_id,firebase_project,firebase_uid) VALUES(?1,?2,?3)').bind(id, FIREBASE_PROJECT, claims.sub)
  ];
  if (previous)
    statements.push(env.DB.prepare('UPDATE user_sessions SET revoked_at=?1 WHERE token_hash=?2 AND revoked_at IS NULL').bind(new Date().toISOString(), await digestKey(previous)));
  await env.DB.batch(statements);
  const response = jsonResponse(request, { authenticated: true, user, expires_at: expiresAt });
  response.headers.set('Set-Cookie', `edgeai_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.max(0, claims.exp - Math.floor(Date.now() / 1000))}`);
  return response;
}
/** Valida cookie, hash da sessão, validade temporal, usuário ativo e vínculo Firebase não revogado em TODA consulta. */
async function getAuthenticatedUser(request, env) {
  if (!env.DB)
    return null;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/);
  if (!match)
    return null;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(match[1]));
  const tokenHash = Array.from(new Uint8Array(digest), x => x.toString(16).padStart(2, "0")).join("");
  return await env.DB.prepare(`
    SELECT u.id, u.full_name
    FROM user_sessions s JOIN users u ON u.id = s.user_id
    JOIN edgeai_firebase_sessions fs ON fs.session_id = s.id
    JOIN edgeai_firebase_identities fi ON fi.firebase_project = fs.firebase_project
      AND fi.firebase_uid = fs.firebase_uid AND fi.user_id = u.id AND fi.revoked_at IS NULL
    WHERE s.token_hash = ?1 AND s.revoked_at IS NULL
      AND datetime(s.expires_at) > datetime('now') AND u.is_active = 1
      AND NOT EXISTS(SELECT 1 FROM edgeai_email_approvals a WHERE a.user_id=u.id AND a.revoked_at IS NOT NULL)
    LIMIT 1
  `).bind(tokenHash).first();
}
/** Obtém identidade exclusivamente da sessão de backend verificada, não de dados enviados pelo navegador. */
async function requestIdentity(request, env) {
  const user = await getAuthenticatedUser(request, env);
  return user ? { user, key: 'user:' + user.id } : null;
}
/* ============================================================================
 * 06 — ADMINISTRAÇÃO E AUDITORIA
 * Painel de gestão restrito ao usuário D1 administrador.
 * ========================================================================== */
/** Prepara um registro de auditoria para inclusão na mesma transação D1 que a alteração administrativa. */
function adminAudit(env, actor, action, target, detail) {
  return env.DB.prepare(`INSERT INTO edgeai_admin_audit(id,actor_user_id,action,target_user_id,detail,created_at)
    VALUES(?1,?2,?3,?4,?5,?6)`).bind(crypto.randomUUID(), actor, action, target, JSON.stringify(detail), new Date().toISOString());
}
/** Aplica autorização administrativa NO SERVIDOR, baseada exclusivamente no usuário D1 usr_frederico. */
async function handleAdminAccess(request, env, url) {
  if (!url.pathname.startsWith('/admin/'))
    return null;
  const reply = (data, status = 200) => jsonResponse(request, data, status);
  const actor = await getAuthenticatedUser(request, env);
  if (!actor)
    return reply({ error: 'Autenticação necessária.' }, 401);
  if (actor.id !== EDGEAI_ADMIN_USER_ID)
    return reply({ error: 'Acesso administrativo negado.' }, 403);
  if ((request.method !== 'GET' || request.headers.has('Origin')) && request.headers.get('Origin') !== url.origin)
    return reply({ error: 'Origem não autorizada.' }, 403);
  if (url.pathname === '/admin/access' && request.method === 'GET') {
    const [users, projects, memberships] = await Promise.all([
      env.DB.prepare(`SELECT u.id,u.full_name,u.is_active,COALESCE(a.email,r.email) AS email,COALESCE(a.revoked_at,i.revoked_at) AS revoked_at,a.claimed_at,
        CASE WHEN i.firebase_uid IS NOT NULL AND i.revoked_at IS NULL THEN 1 ELSE 0 END AS linked
        FROM users u LEFT JOIN edgeai_email_approvals a ON a.user_id=u.id
        LEFT JOIN edgeai_firebase_identities i ON i.user_id=u.id
        LEFT JOIN edgeai_identity_emails r ON r.user_id=u.id ORDER BY u.full_name`).all(),
      env.DB.prepare('SELECT id,name FROM projects ORDER BY name').all(),
      env.DB.prepare('SELECT project_id,user_id,role FROM project_members ORDER BY project_id,user_id').all()
    ]);
    return reply({ users: users.results, projects: projects.results, memberships: memberships.results });
  }
  if (!['POST', 'PATCH'].includes(request.method))
    return reply({ error: 'Método não permitido.' }, 405);
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers.get('Content-Type') || ''))
    return reply({ error: 'Use application/json.' }, 415);
  let body;
  try {
    body = await readJsonBounded(request);
  }
  catch {
    return reply({ error: 'JSON inválido.' }, 400);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body))
    return reply({ error: 'Dados inválidos.' }, 400);
  if (url.pathname === '/admin/users' && request.method === 'POST') {
    const email = normalizedApprovalEmail(body.email);
    const existingId = body.existing_user_id;
    if (!email || existingId !== undefined && (typeof existingId !== 'string' || !/^usr_[a-zA-Z0-9_-]{1,100}$/.test(existingId)))
      return reply({ error: 'E-mail ou usuário inválido.' }, 400);
    let user;
    if (existingId) {
      user = await env.DB.prepare('SELECT id,full_name FROM users WHERE id=?1').bind(existingId).first();
      if (!user)
        return reply({ error: 'Usuário não encontrado.' }, 404);
      if (user.id === EDGEAI_ADMIN_USER_ID)
        return reply({ error: 'A identidade do administrador permanece vinculada por UID.' }, 409);
    }
    else {
      if (typeof body.full_name !== 'string' || !body.full_name.trim() || body.full_name.trim().length > 150)
        return reply({ error: 'Informe o nome (até 150 caracteres).' }, 400);
      user = { id: 'usr_' + crypto.randomUUID(), full_name: body.full_name.trim() };
    }
    const conflict = await env.DB.prepare('SELECT user_id FROM edgeai_email_approvals WHERE email=?1 OR user_id=?2').bind(email, user.id).first();
    const linked = await env.DB.prepare('SELECT user_id FROM edgeai_firebase_identities WHERE user_id=?1').bind(user.id).first();
    if (conflict || linked)
      return reply({ error: 'Usuário ou e-mail já possui aprovação/vínculo. Não será substituído.' }, 409);
    const statements = [];
    if (!existingId)
      statements.push(env.DB.prepare('INSERT INTO users(id,full_name,normalized_name,access_key_hash,is_active) VALUES(?1,?2,?3,?4,1)')
        .bind(user.id, user.full_name, 'firebase-' + user.id, '!firebase-only'));
    statements.push(env.DB.prepare('INSERT INTO edgeai_email_approvals(email,user_id,approved_by,approved_at) VALUES(?1,?2,?3,?4)')
      .bind(email, user.id, actor.id, new Date().toISOString()));
    statements.push(adminAudit(env, actor.id, 'approve_email', user.id, { email, new_user: !existingId }));
    try {
      await env.DB.batch(statements);
    }
    catch {
      return reply({ error: 'Conflito de cadastro. Atualize a lista antes de tentar novamente.' }, 409);
    }
    return reply({ user_id: user.id, status: 'awaiting_verified_login' }, 201);
  }
  const match = url.pathname.match(/^\/admin\/users\/(usr_[a-zA-Z0-9_-]{1,100})\/(status|projects|approval)$/);
  if (!match)
    return reply({ error: 'Rota não encontrada.' }, 404);
  const [, target, action] = match;
  if (target === EDGEAI_ADMIN_USER_ID)
    return reply({ error: 'Acesso do administrador protegido contra remoção pelo painel.' }, 409);
  const user = await env.DB.prepare('SELECT id FROM users WHERE id=?1').bind(target).first();
  if (!user)
    return reply({ error: 'Usuário não encontrado.' }, 404);
  if (action === 'status' && request.method === 'PATCH') {
    if (typeof body.is_active !== 'boolean')
      return reply({ error: 'Estado inválido.' }, 400);
    const statements = [env.DB.prepare('UPDATE users SET is_active=?1 WHERE id=?2').bind(body.is_active ? 1 : 0, target),
    adminAudit(env, actor.id, 'set_active', target, { is_active: body.is_active })];
    // Reactivation never revives an old cookie.
    if (!body.is_active)
      statements.push(env.DB.prepare('UPDATE user_sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL').bind(new Date().toISOString(), target));
    await env.DB.batch(statements);
    return reply({ updated: true });
  }
  if (action === 'approval' && request.method === 'PATCH') {
    if (body.revoke !== true)
      return reply({ error: 'Somente revogação explícita é permitida.' }, 400);
    const now = new Date().toISOString();
    await env.DB.batch([
      env.DB.prepare('UPDATE edgeai_email_approvals SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL').bind(now, target),
      env.DB.prepare('UPDATE edgeai_firebase_identities SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL').bind(now, target),
      env.DB.prepare('UPDATE user_sessions SET revoked_at=?1 WHERE user_id=?2 AND revoked_at IS NULL').bind(now, target),
      adminAudit(env, actor.id, 'revoke_identity', target, {})
    ]);
    return reply({ updated: true });
  }
  if (action === 'projects' && request.method === 'PATCH') {
    if (typeof body.project_id !== 'string' || !validatedProjectId(body.project_id) || !['editor', 'owner', null].includes(body.role))
      return reply({ error: 'Projeto ou papel inválido.' }, 400);
    const project = await env.DB.prepare('SELECT id FROM projects WHERE id=?1').bind(body.project_id).first();
    if (!project)
      return reply({ error: 'Projeto não encontrado.' }, 404);
    const statement = body.role === null
      ? env.DB.prepare('DELETE FROM project_members WHERE project_id=?1 AND user_id=?2').bind(body.project_id, target)
      : env.DB.prepare('INSERT INTO project_members(project_id,user_id,role) VALUES(?1,?2,?3) ON CONFLICT(project_id,user_id) DO UPDATE SET role=excluded.role').bind(body.project_id, target, body.role);
    await env.DB.batch([statement, adminAudit(env, actor.id, 'project_access', target, { project_id: body.project_id, role: body.role })]);
    return reply({ updated: true });
  }
  return reply({ error: 'Método não permitido.' }, 405);
}
/* ============================================================================
 * 07 — ESQUEMAS D1 E COMPATIBILIDADE
 * Criação idempotente de estruturas necessárias aos módulos existentes.
 * ========================================================================== */
/** Mantém as tabelas herdadas usadas pelo chat. Não substitui as migrations 0001/0002, já aplicadas separadamente. */
async function ensureDatabaseSchema(env) {
  if (!env.DB) {
    throw new Error("Binding DB não configurado.");
  }
  // CONVERSATIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS conversations (
      id TEXT PRIMARY KEY,
      user_name TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `).run();
  const conversationColumns = await env.DB.prepare("PRAGMA table_info(conversations)").all();
  const hasUserName = Array.isArray(conversationColumns.results) &&
    conversationColumns.results.some(column => column.name === "user_name");
  if (!hasUserName) {
    await env.DB.prepare(`
      ALTER TABLE conversations
      ADD COLUMN user_name TEXT
    `).run();
  }
  // MESSAGES
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id TEXT NOT NULL,
      role TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (conversation_id)
        REFERENCES conversations(id)
        ON DELETE CASCADE
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_messages_conversation
    ON messages (conversation_id, id)
  `).run();
  // LINKEDIN ACTIONS
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS linkedin_actions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id TEXT,
      user_name TEXT,
      field TEXT NOT NULL,
      instruction TEXT NOT NULL,
      original_message TEXT,
      created_at TEXT NOT NULL,
      email_status TEXT NOT NULL DEFAULT 'pending',
      email_http_status INTEGER,
      email_response TEXT,
      slack_status TEXT NOT NULL DEFAULT 'pending',
      slack_http_status INTEGER,
      slack_response TEXT,
      FOREIGN KEY (conversation_id)
        REFERENCES conversations(id)
        ON DELETE SET NULL
    )
  `).run();
  // MIGRAÇÃO LINKEDIN ACTIONS
  const linkedinColumns = await env.DB.prepare("PRAGMA table_info(linkedin_actions)").all();
  const existingCols = Array.isArray(linkedinColumns.results)
    ? linkedinColumns.results.map(c => c.name)
    : [];
  if (!existingCols.includes("slack_status")) {
    await env.DB.prepare(`
      ALTER TABLE linkedin_actions
      ADD COLUMN slack_status TEXT NOT NULL DEFAULT 'pending'
    `).run();
  }
  if (!existingCols.includes("slack_http_status")) {
    await env.DB.prepare(`
      ALTER TABLE linkedin_actions
      ADD COLUMN slack_http_status INTEGER
    `).run();
  }
  if (!existingCols.includes("slack_response")) {
    await env.DB.prepare(`
      ALTER TABLE linkedin_actions
      ADD COLUMN slack_response TEXT
    `).run();
  }
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_linkedin_actions_conversation
    ON linkedin_actions (conversation_id, id)
  `).run();
}
/** Mantém tabelas de propriedade de PDFs e dados legados de chat público; isso não reativa acesso anônimo. */
async function ensureContentOwnershipSchema(env) {
  if (!env.DB)
    throw new Error("Banco indisponível.");
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS edgeai_pdf_owners (
    file_id TEXT PRIMARY KEY, owner_key TEXT NOT NULL, created_at TEXT NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS edgeai_guest_conversations (
    conversation_id TEXT PRIMARY KEY, owner_key TEXT NOT NULL
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS edgeai_public_limits (
    client_key TEXT PRIMARY KEY, window_hour INTEGER NOT NULL, attempts INTEGER NOT NULL
  )`).run();
}
/** Garante tabelas e índices de documentos dos projetos no D1. */
async function ensureProjectDocumentsSchema(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS edgeai_project_documents (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      file_name TEXT NOT NULL,
      object_key TEXT NOT NULL UNIQUE,
      content_type TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      uploaded_by_user_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(project_id) REFERENCES projects(id),
      FOREIGN KEY(uploaded_by_user_id) REFERENCES users(id)
    )
  `).run();
  await env.DB.prepare(`
    CREATE INDEX IF NOT EXISTS idx_edgeai_project_documents
    ON edgeai_project_documents(project_id, created_at DESC)
  `).run();
}
/* ============================================================================
 * 08 — PERSISTÊNCIA DE CONVERSAS E MENSAGENS
 * Consultas de histórico, metadados e autoria das mensagens.
 * ========================================================================== */
/** Atualiza metadados da conversa sem alterar seu vínculo com projeto ou usuário. */
async function upsertConversation(env, conversationId, userName) {
  const now = new Date().toISOString();
  await env.DB.prepare(`
    INSERT INTO conversations (id, user_name, created_at, updated_at)
    VALUES (?1, ?2, ?3, ?4)
    ON CONFLICT(id) DO UPDATE SET
      user_name = excluded.user_name,
      updated_at = excluded.updated_at
  `).bind(conversationId, userName, now, now).run();
}
/** Persiste uma mensagem com autoria quando houver identidade de usuário. */
async function saveMessage(env, conversationId, role, content, senderUserId = null) {
  if (typeof content !== "string" || !content)
    return;
  await env.DB.prepare(`
    INSERT INTO messages (conversation_id, role, content, created_at, sender_user_id)
    VALUES (?1, ?2, ?3, ?4, ?5)
  `).bind(conversationId, role, content, new Date().toISOString(), senderUserId).run();
}
/** Lê o histórico recente enviado como contexto à API OpenAI. */
async function getConversationHistory(env, conversationId) {
  const result = await env.DB.prepare(`
    SELECT role, content
    FROM (
      SELECT id, role, content
      FROM messages
      WHERE conversation_id = ?1
      ORDER BY id DESC
      LIMIT ?2
    )
    ORDER BY id ASC
  `).bind(conversationId, MAX_HISTORY_MESSAGES).all();
  if (!Array.isArray(result.results))
    return [];
  return result.results
    .filter(item => item && (item.role === "user" || item.role === "assistant") && typeof item.content === "string")
    .map(item => ({ role: item.role, content: item.content }));
}
/** Paginação do histórico de uma conversa já autorizada pela rota chamadora. */
async function fetchConversationMessages(request, env, conversation, projectId = null) {
  const url = new URL(request.url);
  const rawBefore = url.searchParams.get("before");
  if (rawBefore && !/^[1-9][0-9]{0,14}$/.test(rawBefore)) {
    return jsonResponse(request, { error: "Cursor inválido." }, 400);
  }
  const before = rawBefore ? Number(rawBefore) : null;
  const result = await env.DB.prepare(`
    SELECT * FROM (
      SELECT m.id, m.role, m.content, m.created_at, m.sender_user_id,
             u.full_name AS sender_name
      FROM messages m
      LEFT JOIN users u ON u.id = m.sender_user_id
      WHERE m.conversation_id = ?1 AND (?2 IS NULL OR m.id < ?2)
      ORDER BY m.id DESC LIMIT 201
    ) ORDER BY id ASC
  `).bind(conversation.id, before).all();
  const rows = result.results || [];
  const hasMore = rows.length > 200;
  const selected = hasMore ? rows.slice(1) : rows;
  const response = jsonResponse(request, {
    project_id: projectId,
    conversation_id: conversation.id,
    title: conversation.title,
    messages: selected,
    has_more: hasMore,
    next_before: hasMore && selected.length ? selected[0].id : null
  });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
/* ============================================================================
 * 09 — NOTIFICAÇÕES LINKEDIN — RESEND E SLACK
 * Registro e envio assíncrono de notificações, quando solicitado.
 * ========================================================================== */
/** Persiste solicitações explícitas de alteração de perfil antes de notificar o responsável. */
async function saveLinkedInAction(env, context, action) {
  const result = await env.DB.prepare(`
    INSERT INTO linkedin_actions (
      conversation_id, user_name, field, instruction, original_message, created_at, email_status, slack_status
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 'pending')
  `).bind(context.conversationId, context.userName, action.field || "Não informado", action.instruction || "Não informada", context.message || "[Mensagem não informada]", new Date().toISOString()).run();
  return (result && result.meta && result.meta.last_row_id) ? result.meta.last_row_id : null;
}
/** Registra no D1 o resultado da notificação por e-mail. */
async function updateLinkedInEmailStatus(env, actionId, status, httpStatus, responseText) {
  if (!actionId)
    return;
  let safeResponse = String(responseText || "");
  if (safeResponse.length > 5000)
    safeResponse = safeResponse.substring(0, 5000);
  await env.DB.prepare(`
    UPDATE linkedin_actions
    SET email_status = ?1, email_http_status = ?2, email_response = ?3
    WHERE id = ?4
  `).bind(status, httpStatus ?? null, safeResponse, actionId).run();
}
/** Registra no D1 o resultado da notificação pelo Slack. */
async function updateLinkedInSlackStatus(env, actionId, status, httpStatus, responseText) {
  if (!actionId)
    return;
  let safeResponse = String(responseText || "");
  if (safeResponse.length > 5000)
    safeResponse = safeResponse.substring(0, 5000);
  await env.DB.prepare(`
    UPDATE linkedin_actions
    SET slack_status = ?1, slack_http_status = ?2, slack_response = ?3
    WHERE id = ?4
  `).bind(status, httpStatus ?? null, safeResponse, actionId).run();
}
/** Envia notificação de ação LinkedIn pelo Resend, se configurado. */
async function notifyLinkedInUpdateByEmail(env, action, context, actionId) {
  if (!env.RESEND_API_KEY) {
    await updateLinkedInEmailStatus(env, actionId, "missing_resend_key", null, "RESEND_API_KEY não configurada.");
    return;
  }
  if (!env.NOTIFICATION_EMAIL) {
    await updateLinkedInEmailStatus(env, actionId, "missing_notification_email", null, "NOTIFICATION_EMAIL não configurado.");
    return;
  }
  const resendApiKey = String(env.RESEND_API_KEY).trim();
  const notificationEmail = String(env.NOTIFICATION_EMAIL).trim();
  const fromEmail = String(env.RESEND_FROM || "EDGE AI <onboarding@resend.dev>").trim();
  const brasilDateTime = new Intl.DateTimeFormat("pt-BR", {
    timeZone: "America/Sao_Paulo",
    dateStyle: "full",
    timeStyle: "long"
  }).format(new Date());
  const html = `
    <h2>EDGE AI - LinkedIn Action</h2>
    <p><strong>Action ID:</strong> ${escapeHtml(actionId || "")}</p>
    <p><strong>Visitante:</strong> ${escapeHtml(context.userName)}</p>
    <p><strong>Campo:</strong> ${escapeHtml(action.field || "Não informado")}</p>
    <p><strong>Instrução:</strong><br>${nl2br(escapeHtml(action.instruction || "Não informada"))}</p>
    <p><strong>Mensagem original:</strong><br>${nl2br(escapeHtml(context.message || "Não informada"))}</p>
    <p><strong>Conversation ID:</strong> ${escapeHtml(context.conversationId)}</p>
    <p><strong>Data:</strong> ${escapeHtml(brasilDateTime)}</p>
    <p>Backend ${BACKEND_VERSION}</p>
  `;
  const payload = {
    from: fromEmail,
    to: [notificationEmail],
    subject: "EDGEAI-LINKEDIN-ACTION",
    html
  };
  let response;
  try {
    response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${resendApiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
  }
  catch (error) {
    await updateLinkedInEmailStatus(env, actionId, "network_error", null, error?.message || String(error));
    return;
  }
  let responseText = "";
  try {
    responseText = await response.text();
  }
  catch {
    responseText = "Não foi possível ler a resposta da Resend.";
  }
  await updateLinkedInEmailStatus(env, actionId, response.ok ? "accepted" : "failed", response.status, responseText);
}
/** Envia notificação de ação LinkedIn pelo webhook do Slack, se configurado. */
async function notifyLinkedInUpdateBySlack(env, action, context, actionId) {
  if (!env.SLACK_WEBHOOK_URL) {
    await updateLinkedInSlackStatus(env, actionId, "missing_webhook", null, "SLACK_WEBHOOK_URL não configurada.");
    return;
  }
  const webhook = String(env.SLACK_WEBHOOK_URL).trim();
  const slackText = `
EDGEAI_LINKEDIN_ACTION

Action ID: ${actionId || "unknown"}
User: ${context.userName}
Field: ${action.field || "Não informado"}

Instruction:
${action.instruction || "Não informada"}

Original message:
${context.message || "Não informada"}

Conversation ID:
${context.conversationId}

Backend version:
${BACKEND_VERSION}
  `.trim();
  let response;
  try {
    response = await fetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: slackText })
    });
  }
  catch (error) {
    await updateLinkedInSlackStatus(env, actionId, "network_error", null, error?.message || String(error));
    return;
  }
  let responseText = "";
  try {
    responseText = await response.text();
  }
  catch {
    responseText = "Não foi possível ler a resposta do Slack.";
  }
  await updateLinkedInSlackStatus(env, actionId, response.ok ? "accepted" : "failed", response.status, responseText);
}
/* ============================================================================
 * 10 — OPENAI — PREPARAÇÃO E LEITURA DE RESPOSTAS
 * Construção de input e interpretação da saída estruturada.
 * ========================================================================== */
/** Monta o contexto para a Responses API, incluindo histórico, texto e PDFs autorizados. */
function buildOpenAIInput(history, currentMessage, fileIds) {
  const input = [];
  for (const item of history) {
    if (item.role === "user") {
      input.push({
        role: "user",
        content: [{ type: "input_text", text: item.content }]
      });
    }
    else if (item.role === "assistant") {
      input.push({
        role: "assistant",
        content: [{ type: "output_text", text: item.content }]
      });
    }
  }
  const currentContent = [];
  if (typeof currentMessage === "string" && currentMessage.trim()) {
    currentContent.push({
      type: "input_text",
      text: currentMessage.trim()
    });
  }
  if (Array.isArray(fileIds)) {
    for (const fileId of fileIds) {
      if (typeof fileId === "string" && fileId.trim()) {
        currentContent.push({
          type: "input_file",
          file_id: fileId.trim()
        });
      }
    }
  }
  if (currentContent.length === 0) {
    currentContent.push({
      type: "input_text",
      text: "Analise o arquivo enviado."
    });
  }
  input.push({ role: "user", content: currentContent });
  return input;
}
/** Extrai texto da resposta estruturada da OpenAI e trata recusas do modelo. */
function extractOutputText(data) {
  if (typeof data?.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }
  if (!Array.isArray(data?.output))
    return "";
  for (const item of data.output) {
    if (item.type !== "message" || !Array.isArray(item.content))
      continue;
    for (const content of item.content) {
      if (content.type === "output_text" && typeof content.text === "string") {
        return content.text.trim();
      }
      if (content.type === "refusal" && typeof content.refusal === "string") {
        return JSON.stringify({
          message: content.refusal,
          linkedin_action: { required: false, field: "", instruction: "" }
        });
      }
    }
  }
  return "";
}
/* ============================================================================
 * 11 — AUTORIZAÇÃO E ROTAS DE PROJETOS
 * Verificação de project_members e controle de conversas por escopo.
 * ========================================================================== */
/** Consulta a fonte de autorização dos projetos: tabela project_members. */
async function getProjectMembership(env, projectId, userId) {
  return await env.DB.prepare(`
    SELECT p.id, p.name, pm.role
    FROM projects p JOIN project_members pm ON pm.project_id = p.id
    WHERE p.id = ?1 AND pm.user_id = ?2
      AND pm.role IN ('owner','editor')
    LIMIT 1
  `).bind(projectId, userId).first();
}
/** Protege listagem e edição de conversas pessoais e de projetos; verifica escopo e membership. */
async function handlePrivateRoutes(request, env, url) {
  const path = url.pathname;
  const isProjectList = path === "/projects";
  const projectMatch = path.match(/^\/projects\/([A-Za-z0-9_-]{3,100})\/(access|conversations)(?:\/([A-Za-z0-9_-]{5,100})(?:\/(messages))?)?$/);
  const personalMatch = path.match(/^\/me\/conversations(?:\/([A-Za-z0-9_-]{5,100})(?:\/(messages))?)?$/);
  if (!isProjectList && !projectMatch && !personalMatch)
    return null;
  if (!env.DB)
    return jsonResponse(request, { error: "Banco indisponível." }, 503);
  if (!["GET", "POST", "PATCH", "DELETE"].includes(request.method)) {
    return jsonResponse(request, { error: "Método não permitido." }, 405);
  }
  if (request.method !== "GET" && request.headers.get("Origin") !== url.origin) {
    return jsonResponse(request, { error: "Origem não autorizada." }, 403);
  }
  const user = await getAuthenticatedUser(request, env);
  if (!user)
    return jsonResponse(request, { authorized: false, error: "Autenticacao necessaria." }, 401);
  const noStore = (data, status = 200) => {
    const r = jsonResponse(request, data, status);
    r.headers.set("Cache-Control", "no-store");
    return r;
  };
  if (isProjectList) {
    if (request.method !== "GET")
      return noStore({ error: "Método não permitido." }, 405);
    const result = await env.DB.prepare(`
      SELECT p.id, p.name, pm.role
      FROM projects p JOIN project_members pm ON pm.project_id = p.id
      WHERE pm.user_id = ?1 AND pm.role IN ('owner','editor')
      ORDER BY p.name ASC LIMIT 100
    `).bind(user.id).all();
    return noStore({ projects: result.results || [] });
  }
  const projectId = projectMatch ? projectMatch[1] : null;
  const area = projectMatch ? projectMatch[2] : "conversations";
  const conversationId = projectMatch ? projectMatch[3] : personalMatch[1];
  const isMessageRoute = Boolean(projectMatch ? projectMatch[4] : personalMatch[2]);
  let project = null;
  if (projectId) {
    project = await getProjectMembership(env, projectId, user.id);
    if (!project)
      return noStore({ authorized: false, error: "Acesso ao projeto negado." }, 403);
  }
  if (area === "access") {
    if (request.method !== "GET" || conversationId)
      return noStore({ error: "Método não permitido." }, 405);
    return noStore({ authorized: true, project, user });
  }
  const restrictedWhere = projectId ? "project_id = ?2" : "project_id IS NULL AND created_by_user_id = ?2";
  const restrictedOwner = projectId || user.id;
  if (!conversationId) {
    if (request.method === "GET") {
      const where = projectId ? "project_id = ?1" : "project_id IS NULL AND created_by_user_id = ?1";
      const archived = url.searchParams.get("archived") === "1" ? 1 : 0;
      const result = await env.DB.prepare(`
        SELECT id, title, created_at, updated_at, is_archived
        FROM conversations WHERE ${where} AND is_archived = ?2
        ORDER BY updated_at DESC, id DESC LIMIT 100
      `).bind(restrictedOwner, archived).all();
      return noStore({ project_id: projectId, conversations: result.results || [] });
    }
    if (request.method === "POST") {
      const body = await readOptionalJson(request);
      if (!body || (body.title != null && typeof body.title !== "string")) {
        return noStore({ error: "JSON inválido." }, 400);
      }
      const id = crypto.randomUUID();
      const now = new Date().toISOString();
      const title = cleanTitle(body.title);
      await env.DB.prepare(`
        INSERT INTO conversations (id, user_name, created_at, updated_at, project_id, created_by_user_id, title)
        VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6)
      `).bind(id, user.full_name, now, projectId, user.id, title).run();
      return noStore({ conversation_id: id, project_id: projectId, title }, 201);
    }
    return noStore({ error: "Método não permitido." }, 405);
  }
  if (!normalizeConversationId(conversationId))
    return noStore({ error: "Conversa inválida." }, 400);
  const existing = await env.DB.prepare(`
    SELECT id, title, project_id, created_by_user_id, is_archived
    FROM conversations WHERE id = ?1 AND ${restrictedWhere}
    LIMIT 1
  `).bind(conversationId, restrictedOwner).first();
  if (!existing)
    return noStore({ error: "Conversa não encontrada neste espaço." }, 404);
  if (isMessageRoute) {
    if (request.method !== "GET")
      return noStore({ error: "Método não permitido." }, 405);
    return fetchConversationMessages(request, env, existing, projectId);
  }
  if (request.method === "PATCH") {
    const body = await readOptionalJson(request);
    if (!body || (body.title === undefined && body.is_archived === undefined)) {
      return noStore({ error: "Informe title ou is_archived." }, 400);
    }
    if (body.title !== undefined && (typeof body.title !== "string" || !body.title.trim() || body.title.length > 120)) {
      return noStore({ error: "Título inválido." }, 400);
    }
    if (body.is_archived !== undefined && typeof body.is_archived !== "boolean") {
      return noStore({ error: "is_archived inválido." }, 400);
    }
    await env.DB.prepare(`
      UPDATE conversations SET
        title = ?1, is_archived = ?2, updated_at = ?3
      WHERE id = ?4 AND ${restrictedWhere.replace("?2", "?5")}
    `).bind(body.title === undefined ? existing.title : cleanTitle(body.title), body.is_archived === undefined ? existing.is_archived : (body.is_archived ? 1 : 0), new Date().toISOString(), conversationId, restrictedOwner).run();
    return noStore({ updated: true, conversation_id: conversationId });
  }
  if (request.method === "DELETE") {
    await env.DB.prepare("DELETE FROM messages WHERE conversation_id = ?1").bind(conversationId).run();
    await env.DB.prepare(`DELETE FROM conversations WHERE id = ?1 AND ${restrictedWhere}`).bind(conversationId, restrictedOwner).run();
    return noStore({ deleted: true, conversation_id: conversationId });
  }
  return noStore({ error: "Método não permitido." }, 405);
}
/* ============================================================================
 * 12 — DOCUMENTOS DE PROJETO — D1 E R2
 * Upload, listagem, download e remoção com autorização por projeto.
 * ========================================================================== */
/** Gerencia documentos R2/D1 após autenticação e verificação de membership do projeto. */
async function handleProjectDocuments(request, env, url) {
  const match = url.pathname.match(/^\/projects\/([A-Za-z0-9_-]{3,100})\/files(?:\/([A-Za-z0-9_-]{5,100})(?:\/(download))?)?$/);
  const personal = url.pathname.match(/^\/me\/files(?:\/([A-Za-z0-9_-]{5,100})(?:\/(download))?)?$/);
  if (!match && !personal) return null;
  let projectId = match?.[1];
  const documentId = match ? match[2] : personal[1];
  const downloadAction = match ? match[3] : personal[2];
  const table = personal ? 'edgeai_personal_documents' : 'edgeai_project_documents';
  const ownerColumn = personal ? 'user_id' : 'project_id';
  const method = request.method;
  const validMethod = !documentId
    ? ["GET", "POST"].includes(method)
    : downloadAction
      ? method === "GET"
      : method === "DELETE";
  if (!validMethod)
    return jsonResponse(request, { error: "Método não permitido." }, 405);
  if (method !== "GET" && request.headers.get("Origin") !== url.origin) {
    return jsonResponse(request, { error: "Origem não autorizada." }, 403);
  }
  if (!env.DB || !env.FILES_BUCKET) {
    return jsonResponse(request, { error: "D1 ou FILES_BUCKET não configurado." }, 503);
  }
  const user = await getAuthenticatedUser(request, env);
  if (!user)
    return jsonResponse(request, { error: "Autenticacao necessaria." }, 401);
  if (personal) projectId=user.id;
  const membership = personal || await getProjectMembership(env, projectId, user.id);
  if (!membership)
    return jsonResponse(request, { error: "Acesso ao projeto negado." }, 403);
  if (!personal) await ensureProjectDocumentsSchema(env);
  const reply = (data, status = 200) => {
    const res = jsonResponse(request, data, status);
    res.headers.set("Cache-Control", "no-store");
    return res;
  };
  if (!documentId && method === "GET") {
    const result = await env.DB.prepare(`
      SELECT id, file_name, content_type, size_bytes, uploaded_by_user_id, created_at
      FROM ${table}
      WHERE ${ownerColumn} = ?1
      ORDER BY created_at DESC, id DESC LIMIT 200
    `).bind(projectId).all();
    return reply({ project_id: projectId, files: result.results || [] });
  }
  if (!documentId && method === "POST") {
    const contentLength = Number(request.headers.get("Content-Length") || 0);
    if (contentLength > PROJECT_DOCUMENT_LIMIT + 65536) {
      return reply({ error: "Arquivo muito grande. Máximo: 15 MB." }, 413);
    }
    let form;
    try {
      form = await readMultipartBounded(request);
    }
    catch {
      return reply({ error: "Formulário inválido." }, 400);
    }
    const file = form.get("file");
    if (!(file instanceof File))
      return reply({ error: "Selecione um arquivo." }, 400);
    if (file.size <= 0 || file.size > PROJECT_DOCUMENT_LIMIT) {
      return reply({ error: "Tamanho inválido. Limite: 15 MB por arquivo." }, 413);
    }
    const fileName = projectFileSafeName(file.name);
    const ext = fileName.split(".").pop().toLowerCase();
    if (!Object.hasOwn(PROJECT_DOCUMENT_TYPES, ext)) {
      return reply({ error: "Formato não permitido." }, 415);
    }
    const id = crypto.randomUUID();
    const objectKey = `${personal ? 'personal' : 'projects'}/${projectId}/${id}`;
    const contentType = PROJECT_DOCUMENT_TYPES[ext];
    await env.FILES_BUCKET.put(objectKey, await file.arrayBuffer(), {
      httpMetadata: { contentType },
      customMetadata: { projectId, fileId: id }
    });
    try {
      await env.DB.prepare(`
        INSERT INTO ${table}
          (id, ${ownerColumn}, file_name, object_key, content_type, size_bytes, uploaded_by_user_id, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      `).bind(id, projectId, fileName, objectKey, contentType, file.size, user.id, new Date().toISOString()).run();
    }
    catch (error) {
      await env.FILES_BUCKET.delete(objectKey);
      throw error;
    }
    return reply({ id, file_name: fileName, size_bytes: file.size }, 201);
  }
  const item = await env.DB.prepare(`
    SELECT id, file_name, object_key, content_type
    FROM ${table}
    WHERE id = ?1 AND ${ownerColumn} = ?2
    LIMIT 1
  `).bind(documentId, projectId).first();
  if (!item)
    return reply({ error: "Arquivo não encontrado neste projeto." }, 404);
  if (downloadAction && method === "GET") {
    const object = await env.FILES_BUCKET.get(item.object_key);
    if (!object)
      return reply({ error: "Conteúdo do arquivo indisponível." }, 404);
    return new Response(object.body, {
      headers: {
        "Content-Type": item.content_type,
        "Content-Disposition": projectFileDownloadName(item.file_name),
        "Content-Length": String(object.size),
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        ...getCorsHeaders(request)
      }
    });
  }
  if (method === "DELETE") {
    await env.FILES_BUCKET.delete(item.object_key);
    await env.DB.prepare(`
      DELETE FROM ${table} WHERE id = ?1 AND ${ownerColumn} = ?2
    `).bind(documentId, projectId).run();
    return reply({ deleted: true, id: documentId });
  }
  return reply({ error: "Método não permitido." }, 405);
}
/* ============================================================================
 * 13 — CHAT E UPLOAD DE PDFs
 * Fluxos autenticados de conversa, histórico e análise de arquivos.
 * ========================================================================== */
/** Preserva a lógica de quota anterior; usuários autenticados não recebem quota de visitante. */
async function consumePublicQuota(request, env, identity) {
  if (identity.user)
    return null;
  await ensureContentOwnershipSchema(env);
  const clientKey = await digestKey(request.headers.get("CF-Connecting-IP") || "unknown");
  const windowHour = Math.floor(Date.now() / 3600000);
  const row = await env.DB.prepare(`INSERT INTO edgeai_public_limits (client_key, window_hour, attempts)
    VALUES (?1, ?2, 1) ON CONFLICT(client_key) DO UPDATE SET
    attempts = CASE WHEN window_hour = excluded.window_hour THEN attempts + 1 ELSE 1 END,
    window_hour = excluded.window_hour RETURNING attempts`).bind(clientKey, windowHour).first();
  if (row.attempts <= 30)
    return null;
  const response = jsonResponse(request, { error: "Limite do chat público atingido. Tente novamente em uma hora." }, 429);
  response.headers.set("Retry-After", String(3600 - Math.floor(Date.now() / 1000) % 3600));
  return response;
}
/** Recebe PDFs da sessão autenticada e vincula sua propriedade ao usuário D1. */
async function handleUpload(request, env) {
  const identity = await requestIdentity(request, env);
  if (!identity)
    return jsonResponse(request, { error: "Identificação de upload necessária." }, 401);
  if (identity.user && request.headers.get("Origin") !== new URL(request.url).origin) {
    return jsonResponse(request, { error: "Origem não autorizada." }, 403);
  }
  if (Number(request.headers.get("Content-Length") || 0) > PROJECT_DOCUMENT_LIMIT + 65536) {
    return jsonResponse(request, { error: "PDF muito grande. Máximo: 15 MB." }, 413);
  }
  const limited = await consumePublicQuota(request, env, identity);
  if (limited)
    return limited;
  if (!env.OPENAI_API_KEY) {
    return jsonResponse(request, { error: "OPENAI_API_KEY não configurada." }, 500);
  }
  let formData;
  try {
    formData = await readMultipartBounded(request);
  }
  catch {
    return jsonResponse(request, { error: "FormData inválido." }, 400);
  }
  const file = formData.get("file");
  if (!(file instanceof File)) {
    return jsonResponse(request, { error: "Nenhum arquivo recebido." }, 400);
  }
  const fileName = file.name || "arquivo.pdf";
  if (file.size <= 0 || file.size > PROJECT_DOCUMENT_LIMIT) {
    return jsonResponse(request, { error: "Tamanho inválido. Máximo: 15 MB." }, 413);
  }
  if (file.type !== "application/pdf" && !fileName.toLowerCase().endsWith(".pdf")) {
    return jsonResponse(request, { error: "Somente arquivos PDF são permitidos." }, 400);
  }
  const signature = new TextDecoder().decode(await file.slice(0, 5).arrayBuffer());
  if (signature !== "%PDF-")
    return jsonResponse(request, { error: "Conteúdo não é um PDF válido." }, 415);
  const openAIForm = new FormData();
  openAIForm.append("purpose", "user_data");
  openAIForm.append("file", file, fileName);
  let response;
  try {
    response = await fetch("https://api.openai.com/v1/files", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.OPENAI_API_KEY}` },
      body: openAIForm
    });
  }
  catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível conectar à OpenAI durante o upload.",
      detail: "Falha interna; tente novamente."
    }, 502);
  }
  let data;
  try {
    data = await response.json();
  }
  catch {
    return jsonResponse(request, { error: "A OpenAI retornou resposta inválida durante o upload." }, 502);
  }
  if (!response.ok) {
    return jsonResponse(request, {
      error: "Não foi possível enviar o PDF.",
      detail: data?.error?.message || `HTTP ${response.status}`
    }, 502);
  }
  if (typeof data.id !== "string" || !/^file-[A-Za-z0-9_-]{1,150}$/.test(data.id)) {
    return jsonResponse(request, { error: "ID de arquivo inválido recebido da OpenAI." }, 502);
  }
  await ensureContentOwnershipSchema(env);
  await env.DB.prepare(`INSERT INTO edgeai_pdf_owners (file_id, owner_key, created_at) VALUES (?1, ?2, ?3)`)
    .bind(data.id, identity.key, new Date().toISOString()).run();
  return jsonResponse(request, { id: data.id, name: fileName });
}
/** Processa chat somente após autenticação, controle de escopo e validação da propriedade dos PDFs. */
async function handleChat(request, env, ctx) {
  if (!env.OPENAI_API_KEY) {
    return jsonResponse(request, { error: "OPENAI_API_KEY não configurada." }, 500);
  }
  if (!env.DB) {
    return jsonResponse(request, { error: "Banco D1 não configurado." }, 500);
  }
  try {
    await ensureDatabaseSchema(env);
  }
  catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível preparar o banco de dados.",
      detail: "Falha interna; tente novamente."
    }, 500);
  }
  let body;
  try {
    body = await readJsonBounded(request);
  }
  catch {
    return jsonResponse(request, { error: "JSON inválido." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse(request, { error: "JSON deve ser um objeto." }, 400);
  }
  if (body.conversation_id !== undefined && !normalizeConversationId(body.conversation_id)) {
    return jsonResponse(request, { error: "Identificador de conversa inválido." }, 400);
  }
  if (body.message !== undefined && typeof body.message !== "string") {
    return jsonResponse(request, { error: "Mensagem inválida." }, 400);
  }
  if (body.file_ids !== undefined && (!Array.isArray(body.file_ids) || body.file_ids.length > 10 ||
    body.file_ids.some(id => typeof id !== "string" || !/^file-[A-Za-z0-9_-]{1,150}$/.test(id)))) {
    return jsonResponse(request, { error: "Lista de PDFs inválida." }, 400);
  }
  let conversationId = normalizeConversationId(body.conversation_id) || crypto.randomUUID();
  let userName = normalizeUserName(body.user_name);
  const message = typeof body.message === "string" ? body.message.trim() : "";
  const fileIds = Array.isArray(body.file_ids)
    ? body.file_ids.filter(id => typeof id === "string" && id.trim()).slice(0, 10)
    : [];
  if (!message && fileIds.length === 0) {
    return jsonResponse(request, { error: "Envie uma mensagem ou PDF." }, 400);
  }
  if (message.length > 30000) {
    return jsonResponse(request, { error: "Mensagem muito longa." }, 400);
  }
  const requestedProjectId = body.project_id ?? null;
  const requestedPersonal = !requestedProjectId;
  const isPrivateScope = Boolean(requestedProjectId || requestedPersonal);
  if (body.mode !== undefined && body.mode !== "personal" && body.mode !== "public") {
    return jsonResponse(request, { error: "Modo inválido." }, 400);
  }
  if (requestedProjectId !== null && !validatedProjectId(requestedProjectId)) {
    return jsonResponse(request, { error: "Projeto inválido." }, 400);
  }
  if (requestedProjectId && requestedPersonal) {
    return jsonResponse(request, { error: "Modo de conversa inválido." }, 400);
  }
  const existingConversation = await env.DB.prepare(`
    SELECT id, project_id, created_by_user_id
    FROM conversations WHERE id = ?1 LIMIT 1
  `).bind(conversationId).first();
  if (existingConversation && !isPrivateScope &&
    (existingConversation.project_id || existingConversation.created_by_user_id)) {
    return jsonResponse(request, { error: "Conversa não pertence ao chat público." }, 403);
  }
  const identity = await requestIdentity(request, env);
  if (!identity)
    return jsonResponse(request, { error: "Identificação da sessão necessária." }, 401);
  const limited = await consumePublicQuota(request, env, identity);
  if (limited)
    return limited;
  await ensureContentOwnershipSchema(env);
  for (const fileId of fileIds) {
    const owned = await env.DB.prepare("SELECT file_id FROM edgeai_pdf_owners WHERE file_id = ?1 AND owner_key = ?2")
      .bind(fileId, identity.key).first();
    if (!owned)
      return jsonResponse(request, { error: "PDF não pertence a esta sessão." }, 403);
  }
  if (!isPrivateScope) {
    // Reserva a conversa antes de ler seu histórico; a chave não pode ser trocada.
    if (!existingConversation) {
      const now = new Date().toISOString();
      await env.DB.prepare(`INSERT OR IGNORE INTO conversations (id, user_name, created_at, updated_at)
        VALUES (?1, ?2, ?3, ?3)`).bind(conversationId, userName, now).run();
      const persisted = await env.DB.prepare("SELECT id, project_id, created_by_user_id FROM conversations WHERE id = ?1")
        .bind(conversationId).first();
      if (!persisted || persisted.project_id || persisted.created_by_user_id) {
        return jsonResponse(request, { error: "Identificador de conversa já utilizado." }, 409);
      }
      await env.DB.prepare("INSERT OR IGNORE INTO edgeai_guest_conversations (conversation_id, owner_key) VALUES (?1, ?2)")
        .bind(conversationId, identity.key).run();
    }
    const owned = await env.DB.prepare("SELECT conversation_id FROM edgeai_guest_conversations WHERE conversation_id = ?1 AND owner_key = ?2")
      .bind(conversationId, identity.key).first();
    if (!owned)
      return jsonResponse(request, { error: "Conversa pública não pertence a este navegador. Inicie uma nova conversa." }, 403);
  }
  let authenticatedUser = null;
  let accessProjectId = requestedProjectId || existingConversation?.project_id || null;
  if (accessProjectId || requestedPersonal || existingConversation?.created_by_user_id) {
    if (request.headers.get("Origin") !== new URL(request.url).origin) {
      return jsonResponse(request, { error: "Origem não autorizada." }, 403);
    }
    authenticatedUser = await getAuthenticatedUser(request, env);
    if (!authenticatedUser) {
      return jsonResponse(request, { error: "Autenticacao necessaria." }, 401);
    }
    if (accessProjectId) {
      const project = await getProjectMembership(env, accessProjectId, authenticatedUser.id);
      if (!project)
        return jsonResponse(request, { error: "Acesso ao projeto negado." }, 403);
    }
    if (existingConversation) {
      if (existingConversation.project_id !== (requestedProjectId || existingConversation.project_id)) {
        return jsonResponse(request, { error: "Conversa não encontrada neste projeto." }, 404);
      }
      if (requestedPersonal && existingConversation.project_id) {
        return jsonResponse(request, { error: "Conversa não pertence ao espaço pessoal." }, 404);
      }
      if (!existingConversation.project_id && existingConversation.created_by_user_id !== authenticatedUser.id) {
        return jsonResponse(request, { error: "Conversa não autorizada." }, 403);
      }
    }
    userName = authenticatedUser.full_name;
  }
  if (existingConversation && requestedProjectId && existingConversation.project_id !== requestedProjectId) {
    return jsonResponse(request, { error: "Conversa não encontrada neste projeto." }, 404);
  }
  if (existingConversation && requestedPersonal && !existingConversation.created_by_user_id) {
    return jsonResponse(request, { error: "Conversa não pertence ao espaço pessoal." }, 404);
  }
  if (!existingConversation && (requestedProjectId || requestedPersonal)) {
    const now = new Date().toISOString();
    const title = cleanTitle(message, fileIds.length ? "Conversa com PDF" : "Nova conversa");
    await env.DB.prepare(`
      INSERT OR IGNORE INTO conversations (id, user_name, created_at, updated_at, project_id, created_by_user_id, title)
      VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6)
    `).bind(conversationId, userName, now, requestedProjectId, authenticatedUser.id, title).run();
    const persisted = await env.DB.prepare(`
      SELECT project_id, created_by_user_id FROM conversations WHERE id = ?1
    `).bind(conversationId).first();
    if (!persisted || persisted.project_id !== requestedProjectId ||
      (!requestedProjectId && persisted.created_by_user_id !== authenticatedUser.id)) {
      return jsonResponse(request, { error: "Identificador de conversa já utilizado." }, 409);
    }
  }
  let previousHistory;
  try {
    previousHistory = await getConversationHistory(env, conversationId);
  }
  catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível carregar o histórico.",
      detail: "Falha interna; tente novamente."
    }, 500);
  }
  try {
    await upsertConversation(env, conversationId, userName);
    await saveMessage(env, conversationId, "user", message || "[PDF enviado sem texto adicional]", authenticatedUser?.id || null);
  }
  catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível salvar a conversa.",
      detail: "Falha interna; tente novamente."
    }, 500);
  }
  const instructions = BASE_INSTRUCTIONS + `

============================================================
CONTEXTO DO VISITANTE
============================================================

Nome informado:
${userName}

Conversation ID:
${conversationId}
`;
  let openAIResponse;
  try {
    openAIResponse = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${env.OPENAI_API_KEY}`
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || DEFAULT_MODEL,
        instructions,
        input: buildOpenAIInput(previousHistory, message, fileIds),
        text: { format: RESPONSE_FORMAT },
        store: false
      })
    });
  }
  catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível conectar à OpenAI.",
      detail: "Falha interna; tente novamente."
    }, 502);
  }
  let openAIData;
  try {
    openAIData = await openAIResponse.json();
  }
  catch {
    return jsonResponse(request, { error: "A OpenAI retornou uma resposta inválida." }, 502);
  }
  if (!openAIResponse.ok) {
    return jsonResponse(request, {
      error: "Falha ao consultar a OpenAI.",
      detail: openAIData?.error?.message || `HTTP ${openAIResponse.status}`
    }, 502);
  }
  const rawOutput = extractOutputText(openAIData);
  if (!rawOutput) {
    return jsonResponse(request, { error: "A OpenAI não retornou conteúdo." }, 502);
  }
  let result;
  try {
    result = JSON.parse(rawOutput);
  }
  catch {
    return jsonResponse(request, { error: "A IA retornou resposta em formato inesperado." }, 502);
  }
  if (!result || typeof result.message !== "string") {
    return jsonResponse(request, { error: "Resposta estruturada inválida." }, 502);
  }
  try {
    await saveMessage(env, conversationId, "assistant", result.message);
    await upsertConversation(env, conversationId, userName);
  }
  catch (error) {
    console.error("ASSISTANT DATABASE ERROR:", error);
  }
  if (result.linkedin_action && result.linkedin_action.required === true) {
    const context = { conversationId, userName, message };
    let actionId = null;
    try {
      actionId = await saveLinkedInAction(env, context, result.linkedin_action);
    }
    catch (error) {
      console.error("LINKEDIN ACTION DATABASE ERROR:", error);
    }
    ctx.waitUntil(Promise.allSettled([
      notifyLinkedInUpdateByEmail(env, result.linkedin_action, context, actionId),
      notifyLinkedInUpdateBySlack(env, result.linkedin_action, context, actionId)
    ]));
  }
  return jsonResponse(request, {
    message: result.message,
    conversation_id: conversationId
  });
}
/* ============================================================================
 * 14 — SAÚDE DO SERVIÇO
 * Verificação de dependências e configuração do Worker.
 * ========================================================================== */
/** Consulta disponibilidade de banco e configuração de serviços sem expor valores de segredos. */
async function handleHealth(request, env) {
  let databaseStatus = "error";
  try {
    await ensureDatabaseSchema(env);
    await env.DB.prepare("SELECT COUNT(*) AS total FROM conversations").first();
    databaseStatus = "ok";
  }
  catch (error) {
    console.error("HEALTH DATABASE ERROR:", error);
  }
  const openAIStatus = env.OPENAI_API_KEY ? "configured" : "missing";
  const resendStatus = env.RESEND_API_KEY ? "configured" : "missing";
  const emailStatus = env.NOTIFICATION_EMAIL ? "configured" : "missing";
  const resendFromStatus = env.RESEND_FROM ? "configured" : "default";
  const slackStatus = env.SLACK_WEBHOOK_URL ? "configured" : "missing";
  const overallStatus = databaseStatus === "ok" && openAIStatus === "configured" ? "ok" : "error";
  return jsonResponse(request, {
    status: overallStatus,
    service: "EDGE AI Backend",
    version: BACKEND_VERSION,
    database: databaseStatus,
    openai_key: openAIStatus,
    resend_api_key: resendStatus,
    resend_from: resendFromStatus,
    notification_email: emailStatus,
    slack_webhook: slackStatus
  }, overallStatus === "ok" ? 200 : 500);
}
/* ============================================================================
 * 15 — ENTRADA HTTP E DESPACHO DE ROTAS
 * Centraliza políticas gerais e roteamento Cloudflare Workers.
 * ========================================================================== */
/** Ponto de entrada do Cloudflare Worker: políticas HTTP, autenticação e despacho de rotas. */
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const origin = request.headers.get("Origin");
      if (origin && !isAllowedOrigin(origin)) {
        return jsonResponse(request, { error: "Origin não autorizado." }, 403);
      }
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: getCorsHeaders(request)
        });
      }
      if (["POST", "PATCH", "DELETE"].includes(request.method)) {
        if (!origin || !ALLOWED_ORIGINS.includes(origin) || request.headers.get("Sec-Fetch-Site") === "cross-site" && origin !== ALLOWED_ORIGINS[0]) {
          return jsonResponse(request, { error: "Origem não autorizada." }, 403);
        }
        if ((url.pathname === "/chat" || url.pathname === "/auth/firebase" || url.pathname === "/auth/login" || request.method === "PATCH") &&
          !/^application\/json(?:\s*;|$)/i.test(request.headers.get("Content-Type") || "")) {
          return jsonResponse(request, { error: "Content-Type deve ser application/json." }, 415);
        }
        if (!url.pathname.endsWith("/files") && url.pathname !== "/upload" &&
          Number(request.headers.get("Content-Length") || 0) > 131072) {
          return jsonResponse(request, { error: "Requisição muito grande." }, 413);
        }
      }
      // FRONTEND
      if (request.method === "GET" && (url.pathname === "/app" || url.pathname === "/app/")) {
        try {
          // Pin the reviewed frontend so the Worker deploy is independent of Pages propagation.
          const frontendResponse = await fetch("https://raw.githubusercontent.com/FredericoFahndrich/EdgeAI/e03b6af34e825818b4bd4bb6b7328a7c45d88b5d/index.html");
          if (!frontendResponse.ok)
            throw new Error("Frontend indisponível.");
          const html = (await frontendResponse.text()).replace('<head>', '<head><base href="https://fredericofahndrich.github.io/EdgeAI/">');
          return new Response(html, {
            status: 200,
            headers: {
              "Content-Type": "text/html; charset=utf-8",
              "Cache-Control": "no-store",
              "X-Content-Type-Options": "nosniff",
              "X-Frame-Options": "DENY"
            }
          });
        }
        catch {
          return jsonResponse(request, { error: "Não foi possível carregar o EDGE AI." }, 502);
        }
      }
      // SESSÃO
      if (request.method === "GET" && url.pathname === "/auth/session") {
        const user = await getAuthenticatedUser(request, env);
        const response = jsonResponse(request, {
          authenticated: Boolean(user),
          user: user ? { ...user, is_admin: user.id === EDGEAI_ADMIN_USER_ID } : null
        });
        response.headers.set("Cache-Control", "no-store");
        return response;
      }
      if (request.method === 'POST' && url.pathname === '/auth/firebase') {
        return await exchangeFirebaseSession(request, env);
      }
      if (url.pathname === '/auth/login') {
        return jsonResponse(request, { error: 'Use o login Firebase.', code: 'firebase_required' }, 410);
      }
      // LOGOUT
      if (request.method === "POST" && url.pathname === "/auth/logout") {
        if (request.headers.get("Origin") !== url.origin) {
          return jsonResponse(request, { error: "Origem não autorizada." }, 403);
        }
        if (!env.DB) {
          return jsonResponse(request, { error: "Banco indisponível." }, 503);
        }
        const cookieHeader = request.headers.get("Cookie") || "";
        const match = cookieHeader.match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/);
        if (match) {
          const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(match[1]));
          const tokenHash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
          await env.DB.prepare(`
            UPDATE user_sessions
            SET revoked_at = ?1
            WHERE token_hash = ?2 AND revoked_at IS NULL
          `).bind(new Date().toISOString(), tokenHash).run();
        }
        const response = jsonResponse(request, { authenticated: false, message: "Sessão encerrada." });
        response.headers.set("Set-Cookie", "edgeai_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
        response.headers.set("Cache-Control", "no-store");
        return response;
      }
      // Authenticate every data route before parsing bodies, uploads or provider calls.
      if ((url.pathname === '/chat' || url.pathname === '/upload' || url.pathname === '/projects' ||
        url.pathname.startsWith('/projects/') || url.pathname.startsWith('/me/')) &&
        !await getAuthenticatedUser(request, env)) {
        return jsonResponse(request, { error: 'Autenticação necessária.' }, 401);
      }
      const membersResponse = await handleProjectMembers(request,env,url,{authenticate:getAuthenticatedUser,reply:jsonResponse,readJson:readJsonBounded});
      if(membersResponse) return membersResponse;
      const adminResponse = await handleAdminAccess(request, env, url);
      if (adminResponse)
        return adminResponse;
      // GESTÃO DE DOCUMENTOS DE PROJETO (R2)
      const documentResponse = await handleProjectDocuments(request, env, url);
      if (documentResponse)
        return documentResponse;
      // ROTAS PRIVADAS (PROJECTS & PERSONAL CONVERSATIONS)
      const privateResponse = await handlePrivateRoutes(request, env, url);
      if (privateResponse)
        return privateResponse;
      // HEALTH
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
        return await handleHealth(request, env);
      }
      // UPLOAD DIRETO PARA OPENAI (PDF)
      if (request.method === "POST" && url.pathname === "/upload") {
        return await handleUpload(request, env);
      }
      // CHAT
      if (request.method === "POST" && url.pathname === "/chat") {
        return await handleChat(request, env, ctx);
      }
      // 404
      return jsonResponse(request, { error: "Endpoint não encontrado." }, 404);
    }
    catch (error) {
      console.error("EDGEAI_REQUEST_FAILED");
      return jsonResponse(request, {
        error: "Erro interno no backend.",
        // Detalhes ficam apenas nos logs do servidor.
      }, 500);
    }
  }
};
