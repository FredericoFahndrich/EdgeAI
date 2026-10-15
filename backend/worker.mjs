// Fixed issuer/key source: never accept a token-supplied URL or project.
const FIREBASE_PROJECT = 'edgeai-auth';
const FIREBASE_JWKS = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
let firebaseKeyCache = { until: 0, keys: [] };
let firebaseKeyRequest;
function decodeFirebasePart(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Invalid token');
  return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
}
async function firebaseKeys() {
  if (firebaseKeyCache.until > Date.now()) return firebaseKeyCache.keys;
  if (!firebaseKeyRequest) firebaseKeyRequest = (async () => {
    const response = await fetch(FIREBASE_JWKS, {signal: AbortSignal.timeout(8000), redirect:'error'});
    if (!response.ok) throw new Error('Key service unavailable');
    const data = await response.json();
    if (!Array.isArray(data.keys) || !data.keys.length) throw new Error('Invalid key set');
    const maxAge = Number((response.headers.get('Cache-Control') || '').match(/max-age=(\d+)/)?.[1] || 300);
    firebaseKeyCache = {keys:data.keys, until:Date.now()+Math.min(maxAge,3600)*1000};
    return data.keys;
  })().finally(() => { firebaseKeyRequest = null; });
  return firebaseKeyRequest;
}
async function verifyFirebaseIdToken(token) {
  if (typeof token !== 'string' || token.length > 16384) throw new Error('Invalid token');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const header = JSON.parse(new TextDecoder().decode(decodeFirebasePart(parts[0])));
  const claims = JSON.parse(new TextDecoder().decode(decodeFirebasePart(parts[1])));
  const now = Math.floor(Date.now()/1000);
  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length > 256 || header.crit ||
      claims.iss !== 'https://securetoken.google.com/' + FIREBASE_PROJECT || claims.aud !== FIREBASE_PROJECT ||
      typeof claims.sub !== 'string' || !claims.sub.length || claims.sub.length > 128 ||
      !Number.isInteger(claims.exp) || claims.exp <= now ||
      !Number.isInteger(claims.iat) || claims.iat > now || claims.iat >= claims.exp ||
      !Number.isInteger(claims.auth_time) || claims.auth_time > now || claims.auth_time > claims.iat ||
      claims.firebase?.tenant || !['google.com','password'].includes(claims.firebase?.sign_in_provider)) {
    throw new Error('Invalid token');
  }
  const jwk = (await firebaseKeys()).find(k => k.kid === header.kid && k.kty === 'RSA');
  if (!jwk) throw new Error('Unknown signing key');
  const key = await crypto.subtle.importKey('jwk', jwk, {name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'}, false, ['verify']);
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decodeFirebasePart(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1]))) {
    throw new Error('Invalid signature');
  }
  return claims;
}
async function exchangeFirebaseSession(request, env) {
  if (request.headers.get('Origin') !== new URL(request.url).origin) return jsonResponse(request,{error:'Abra o EDGE AI pelo endereço /app do Worker.'},403);
  if (!env.DB) return jsonResponse(request,{error:'Banco indisponível.'},503);
  const key = await digestKey('firebase:'+(request.headers.get('CF-Connecting-IP') || 'unknown'));
  const limit = await env.DB.prepare(`INSERT INTO auth_login_limits(client_key,window_minute,attempts)
    VALUES(?1,?2,1) ON CONFLICT(client_key) DO UPDATE SET
    attempts=CASE WHEN window_minute=excluded.window_minute THEN attempts+1 ELSE 1 END,
    window_minute=excluded.window_minute RETURNING attempts`).bind(key,Math.floor(Date.now()/60000)).first();
  if (limit.attempts > 20) return jsonResponse(request,{error:'Muitas tentativas. Aguarde um minuto.'},429);
  let claims;
  try {
    const body = await readJsonBounded(request);
    claims = await verifyFirebaseIdToken(body?.idToken);
  } catch { return jsonResponse(request,{error:'Token Firebase inválido ou validação indisponível.'},401); }
  const user = await env.DB.prepare(`SELECT u.id,u.full_name FROM edgeai_firebase_identities i
    JOIN users u ON u.id=i.user_id WHERE i.firebase_project=?1 AND i.firebase_uid=?2
    AND i.revoked_at IS NULL AND u.is_active=1`).bind(FIREBASE_PROJECT,claims.sub).first();
  if (!user) return jsonResponse(request,{error:'Conta autenticada, mas ainda sem vínculo administrativo de acesso.',code:'identity_not_approved'},403);
  // A session never outlives the signed ID token. Refresh requires another verified token.
  const token = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const id = crypto.randomUUID(), tokenHash = await digestKey(token);
  const expiresAt = new Date(claims.exp*1000).toISOString();
  const previous = (request.headers.get('Cookie')||'').match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/)?.[1];
  const statements = [
    env.DB.prepare('INSERT INTO user_sessions(id,user_id,token_hash,expires_at) VALUES(?1,?2,?3,?4)').bind(id,user.id,tokenHash,expiresAt),
    env.DB.prepare('INSERT INTO edgeai_firebase_sessions(session_id,firebase_project,firebase_uid) VALUES(?1,?2,?3)').bind(id,FIREBASE_PROJECT,claims.sub)
  ];
  if (previous) statements.push(env.DB.prepare('UPDATE user_sessions SET revoked_at=?1 WHERE token_hash=?2 AND revoked_at IS NULL').bind(new Date().toISOString(),await digestKey(previous)));
  await env.DB.batch(statements);
  const response = jsonResponse(request,{authenticated:true,user,expires_at:expiresAt});
  response.headers.set('Set-Cookie',`edgeai_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${Math.max(0,claims.exp-Math.floor(Date.now()/1000))}`);
  return response;
}

/**
 * ============================================================
 * EDGE AI BACKEND
 * Cloudflare Worker + D1 + OpenAI + Resend + Slack + R2
 * Version: 2.7.0
 * ============================================================
 */

const BACKEND_VERSION = "3.0.0";
const DEFAULT_MODEL = "gpt-5";
const MAX_HISTORY_MESSAGES = 20;

/**
 * ============================================================
 * ORIGENS PERMITIDAS
 * ============================================================
 */
const ALLOWED_ORIGINS = [
  "https://fredericofahndrich.github.io",
  "https://edgeai-backend.frederico-fahndrich.workers.dev",
  "http://localhost:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
];

/**
 * ============================================================
 * INSTRUÇÕES DA IA
 * ============================================================
 */
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

/**
 * ============================================================
 * STRUCTURED OUTPUT
 * ============================================================
 */
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

/**
 * ============================================================
 * CORS & RESPOSTAS HTTP
 * ============================================================
 */
function isAllowedOrigin(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin");
  const allowedOrigin = origin && ALLOWED_ORIGINS.includes(origin) ? origin : null;

  return {
    ...(allowedOrigin ? {"Access-Control-Allow-Origin": allowedOrigin, "Access-Control-Allow-Credentials": "true"} : {}),
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, X-EdgeAI-Guest",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

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

/**
 * ============================================================
 * BANCO DE DADOS - SCHEMAS E MIGRAÇÕES
 * ============================================================
 */
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

/**
 * ============================================================
 * NORMALIZAÇÃO E UTILITÁRIOS
 * ============================================================
 */
function normalizeConversationId(value) {
  if (typeof value !== "string") return "";
  const id = value.trim();
  if (id.length < 5 || id.length > 100) return "";
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) return "";
  return id;
}

function normalizeUserName(value) {
  if (typeof value !== "string") return "Visitante";
  let name = value.trim();
  if (!name) return "Visitante";
  if (name.length > 80) name = name.substring(0, 80);
  return name;
}

function validatedProjectId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{3,100}$/.test(value) ? value : null;
}

function cleanTitle(value, fallback = "Nova conversa") {
  const s = typeof value === "string" ? value.trim().replace(/\s+/g, " ") : "";
  return (s || fallback).slice(0, 120);
}

async function readOptionalJson(request) {
  try {
    const body = await readJsonBounded(request);
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch {
    return null;
  }
}

function escapeHtml(text) {
  return String(text)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function nl2br(text) {
  return String(text).replace(/\n/g, "<br>");
}

/**
 * ============================================================
 * OPERAÇÕES NO BANCO (D1)
 * ============================================================
 */
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

async function saveMessage(env, conversationId, role, content, senderUserId = null) {
  if (typeof content !== "string" || !content) return;
  await env.DB.prepare(`
    INSERT INTO messages (conversation_id, role, content, created_at, sender_user_id)
    VALUES (?1, ?2, ?3, ?4, ?5)
  `).bind(conversationId, role, content, new Date().toISOString(), senderUserId).run();
}

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

  if (!Array.isArray(result.results)) return [];

  return result.results
    .filter(item => item && (item.role === "user" || item.role === "assistant") && typeof item.content === "string")
    .map(item => ({ role: item.role, content: item.content }));
}

async function saveLinkedInAction(env, context, action) {
  const result = await env.DB.prepare(`
    INSERT INTO linkedin_actions (
      conversation_id, user_name, field, instruction, original_message, created_at, email_status, slack_status
    )
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 'pending')
  `).bind(
    context.conversationId,
    context.userName,
    action.field || "Não informado",
    action.instruction || "Não informada",
    context.message || "[Mensagem não informada]",
    new Date().toISOString()
  ).run();

  return (result && result.meta && result.meta.last_row_id) ? result.meta.last_row_id : null;
}

async function updateLinkedInEmailStatus(env, actionId, status, httpStatus, responseText) {
  if (!actionId) return;
  let safeResponse = String(responseText || "");
  if (safeResponse.length > 5000) safeResponse = safeResponse.substring(0, 5000);

  await env.DB.prepare(`
    UPDATE linkedin_actions
    SET email_status = ?1, email_http_status = ?2, email_response = ?3
    WHERE id = ?4
  `).bind(status, httpStatus ?? null, safeResponse, actionId).run();
}

async function updateLinkedInSlackStatus(env, actionId, status, httpStatus, responseText) {
  if (!actionId) return;
  let safeResponse = String(responseText || "");
  if (safeResponse.length > 5000) safeResponse = safeResponse.substring(0, 5000);

  await env.DB.prepare(`
    UPDATE linkedin_actions
    SET slack_status = ?1, slack_http_status = ?2, slack_response = ?3
    WHERE id = ?4
  `).bind(status, httpStatus ?? null, safeResponse, actionId).run();
}

/**
 * ============================================================
 * AUTENTICAÇÃO E SESSÃO
 * ============================================================
 */
async function getAuthenticatedUser(request, env) {
  if (!env.DB) return null;
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)edgeai_session=([A-Za-z0-9_-]{43})(?:;|$)/);
  if (!match) return null;

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
    LIMIT 1
  `).bind(tokenHash).first();
}

async function getProjectMembership(env, projectId, userId) {
  return await env.DB.prepare(`
    SELECT p.id, p.name, pm.role
    FROM projects p JOIN project_members pm ON pm.project_id = p.id
    WHERE p.id = ?1 AND pm.user_id = ?2
      AND pm.role IN ('owner','editor')
    LIMIT 1
  `).bind(projectId, userId).first();
}

/**
 * ============================================================
 * INTEGRAÇÕES EXTERNAS (RESEND & SLACK)
 * ============================================================
 */
async function ensureContentOwnershipSchema(env) {
  if (!env.DB) throw new Error("Banco indisponível.");
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

async function readBoundedBody(request, limit) {
  const reader=request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks=[];let size=0;
  for (;;) {
    const {done,value}=await reader.read();if(done) break;
    size+=value.byteLength;
    if (size>limit) {await reader.cancel();throw new Error("Requisição excede o limite de tamanho.");}
    chunks.push(value);
  }
  const result=new Uint8Array(size);let offset=0;
  for(const chunk of chunks){result.set(chunk,offset);offset+=chunk.byteLength;}
  return result;
}

async function readJsonBounded(request) {
  return JSON.parse(new TextDecoder().decode(await readBoundedBody(request,131072)));
}

async function readMultipartBounded(request) {
  return new Response(await readBoundedBody(request,15*1024*1024+65536), {
    headers:{"Content-Type":request.headers.get("Content-Type")||""}
  }).formData();
}

async function digestKey(value) {
  const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,"0")).join("");
}

async function requestIdentity(request, env) {
  const user = await getAuthenticatedUser(request, env);
  return user ? {user,key:'user:'+user.id} : null;
}

async function consumePublicQuota(request, env, identity) {
  if (identity.user) return null;
  await ensureContentOwnershipSchema(env);
  const clientKey = await digestKey(request.headers.get("CF-Connecting-IP") || "unknown");
  const windowHour = Math.floor(Date.now()/3600000);
  const row = await env.DB.prepare(`INSERT INTO edgeai_public_limits (client_key, window_hour, attempts)
    VALUES (?1, ?2, 1) ON CONFLICT(client_key) DO UPDATE SET
    attempts = CASE WHEN window_hour = excluded.window_hour THEN attempts + 1 ELSE 1 END,
    window_hour = excluded.window_hour RETURNING attempts`).bind(clientKey, windowHour).first();
  if (row.attempts <= 30) return null;
  const response = jsonResponse(request, {error: "Limite do chat público atingido. Tente novamente em uma hora."}, 429);
  response.headers.set("Retry-After", String(3600 - Math.floor(Date.now()/1000)%3600));
  return response;
}

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
  } catch (error) {
    await updateLinkedInEmailStatus(env, actionId, "network_error", null, error?.message || String(error));
    return;
  }

  let responseText = "";
  try {
    responseText = await response.text();
  } catch {
    responseText = "Não foi possível ler a resposta da Resend.";
  }

  await updateLinkedInEmailStatus(env, actionId, response.ok ? "accepted" : "failed", response.status, responseText);
}

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
  } catch (error) {
    await updateLinkedInSlackStatus(env, actionId, "network_error", null, error?.message || String(error));
    return;
  }

  let responseText = "";
  try {
    responseText = await response.text();
  } catch {
    responseText = "Não foi possível ler a resposta do Slack.";
  }

  await updateLinkedInSlackStatus(env, actionId, response.ok ? "accepted" : "failed", response.status, responseText);
}

/**
 * ============================================================
 * OPENAI UTILS
 * ============================================================
 */
function buildOpenAIInput(history, currentMessage, fileIds) {
  const input = [];

  for (const item of history) {
    if (item.role === "user") {
      input.push({
        role: "user",
        content: [{ type: "input_text", text: item.content }]
      });
    } else if (item.role === "assistant") {
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

function extractOutputText(data) {
  if (typeof data?.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

  if (!Array.isArray(data?.output)) return "";

  for (const item of data.output) {
    if (item.type !== "message" || !Array.isArray(item.content)) continue;

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

/**
 * ============================================================
 * EDGE AI 2.6 - GESTÃO DE DOCUMENTOS DE PROJETO (R2 + D1)
 * ============================================================
 */
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

function projectFileSafeName(name) {
  return String(name || "arquivo")
    .replace(/[\\/\x00-\x1f\x7f]/g, "_")
    .replace(/[\r\n]/g, " ")
    .trim().slice(0, 180) || "arquivo";
}

function projectFileDownloadName(name) {
  const ascii = String(name)
    .normalize("NFKD")
    .replace(/[^\x20-\x7e]/g, "_")
    .replace(/["\\]/g, "_");
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function handleProjectDocuments(request, env, url) {
  const match = url.pathname.match(
    /^\/projects\/([A-Za-z0-9_-]{3,100})\/files(?:\/([A-Za-z0-9_-]{5,100})(?:\/(download))?)?$/
  );
  if (!match) return null;

  const [, projectId, documentId, downloadAction] = match;
  const method = request.method;
  const validMethod = !documentId
    ? ["GET", "POST"].includes(method)
    : downloadAction
      ? method === "GET"
      : method === "DELETE";

  if (!validMethod) return jsonResponse(request, { error: "Método não permitido." }, 405);
  if (method !== "GET" && request.headers.get("Origin") !== url.origin) {
    return jsonResponse(request, { error: "Origem não autorizada." }, 403);
  }
  if (!env.DB || !env.FILES_BUCKET) {
    return jsonResponse(request, { error: "D1 ou FILES_BUCKET não configurado." }, 503);
  }

  const user = await getAuthenticatedUser(request, env);
  if (!user) return jsonResponse(request, { error: "Autenticacao necessaria." }, 401);

  const membership = await getProjectMembership(env, projectId, user.id);
  if (!membership) return jsonResponse(request, { error: "Acesso ao projeto negado." }, 403);

  await ensureProjectDocumentsSchema(env);
  const reply = (data, status = 200) => {
    const res = jsonResponse(request, data, status);
    res.headers.set("Cache-Control", "no-store");
    return res;
  };

  if (!documentId && method === "GET") {
    const result = await env.DB.prepare(`
      SELECT id, file_name, content_type, size_bytes, uploaded_by_user_id, created_at
      FROM edgeai_project_documents
      WHERE project_id = ?1
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
    } catch {
      return reply({ error: "Formulário inválido." }, 400);
    }

    const file = form.get("file");
    if (!(file instanceof File)) return reply({ error: "Selecione um arquivo." }, 400);
    if (file.size <= 0 || file.size > PROJECT_DOCUMENT_LIMIT) {
      return reply({ error: "Tamanho inválido. Limite: 15 MB por arquivo." }, 413);
    }

    const fileName = projectFileSafeName(file.name);
    const ext = fileName.split(".").pop().toLowerCase();
    if (!Object.hasOwn(PROJECT_DOCUMENT_TYPES, ext)) {
      return reply({ error: "Formato não permitido." }, 415);
    }

    const id = crypto.randomUUID();
    const objectKey = `projects/${projectId}/${id}`;
    const contentType = PROJECT_DOCUMENT_TYPES[ext];

    await env.FILES_BUCKET.put(objectKey, await file.arrayBuffer(), {
      httpMetadata: { contentType },
      customMetadata: { projectId, fileId: id }
    });

    try {
      await env.DB.prepare(`
        INSERT INTO edgeai_project_documents
          (id, project_id, file_name, object_key, content_type, size_bytes, uploaded_by_user_id, created_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
      `).bind(id, projectId, fileName, objectKey, contentType, file.size, user.id, new Date().toISOString()).run();
    } catch (error) {
      await env.FILES_BUCKET.delete(objectKey);
      throw error;
    }

    return reply({ id, file_name: fileName, size_bytes: file.size }, 201);
  }

  const item = await env.DB.prepare(`
    SELECT id, file_name, object_key, content_type
    FROM edgeai_project_documents
    WHERE id = ?1 AND project_id = ?2
    LIMIT 1
  `).bind(documentId, projectId).first();

  if (!item) return reply({ error: "Arquivo não encontrado neste projeto." }, 404);

  if (downloadAction && method === "GET") {
    const object = await env.FILES_BUCKET.get(item.object_key);
    if (!object) return reply({ error: "Conteúdo do arquivo indisponível." }, 404);
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
      DELETE FROM edgeai_project_documents WHERE id = ?1 AND project_id = ?2
    `).bind(documentId, projectId).run();
    return reply({ deleted: true, id: documentId });
  }

  return reply({ error: "Método não permitido." }, 405);
}

/**
 * ============================================================
 * ROTAS PRIVADAS (PROJECTS & PERSONAL CONVERSATIONS)
 * ============================================================
 */
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

async function handlePrivateRoutes(request, env, url) {
  const path = url.pathname;
  const isProjectList = path === "/projects";
  const projectMatch = path.match(/^\/projects\/([A-Za-z0-9_-]{3,100})\/(access|conversations)(?:\/([A-Za-z0-9_-]{5,100})(?:\/(messages))?)?$/);
  const personalMatch = path.match(/^\/me\/conversations(?:\/([A-Za-z0-9_-]{5,100})(?:\/(messages))?)?$/);

  if (!isProjectList && !projectMatch && !personalMatch) return null;
  if (!env.DB) return jsonResponse(request, { error: "Banco indisponível." }, 503);

  if (!["GET", "POST", "PATCH", "DELETE"].includes(request.method)) {
    return jsonResponse(request, { error: "Método não permitido." }, 405);
  }
  if (request.method !== "GET" && request.headers.get("Origin") !== url.origin) {
    return jsonResponse(request, { error: "Origem não autorizada." }, 403);
  }

  const user = await getAuthenticatedUser(request, env);
  if (!user) return jsonResponse(request, { authorized: false, error: "Autenticacao necessaria." }, 401);

  const noStore = (data, status = 200) => {
    const r = jsonResponse(request, data, status);
    r.headers.set("Cache-Control", "no-store");
    return r;
  };

  if (isProjectList) {
    if (request.method !== "GET") return noStore({ error: "Método não permitido." }, 405);
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
    if (!project) return noStore({ authorized: false, error: "Acesso ao projeto negado." }, 403);
  }

  if (area === "access") {
    if (request.method !== "GET" || conversationId) return noStore({ error: "Método não permitido." }, 405);
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

  if (!normalizeConversationId(conversationId)) return noStore({ error: "Conversa inválida." }, 400);

  const existing = await env.DB.prepare(`
    SELECT id, title, project_id, created_by_user_id, is_archived
    FROM conversations WHERE id = ?1 AND ${restrictedWhere}
    LIMIT 1
  `).bind(conversationId, restrictedOwner).first();

  if (!existing) return noStore({ error: "Conversa não encontrada neste espaço." }, 404);

  if (isMessageRoute) {
    if (request.method !== "GET") return noStore({ error: "Método não permitido." }, 405);
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
    `).bind(
      body.title === undefined ? existing.title : cleanTitle(body.title),
      body.is_archived === undefined ? existing.is_archived : (body.is_archived ? 1 : 0),
      new Date().toISOString(), conversationId, restrictedOwner
    ).run();

    return noStore({ updated: true, conversation_id: conversationId });
  }

  if (request.method === "DELETE") {
    await env.DB.prepare("DELETE FROM messages WHERE conversation_id = ?1").bind(conversationId).run();
    await env.DB.prepare(`DELETE FROM conversations WHERE id = ?1 AND ${restrictedWhere}`).bind(conversationId, restrictedOwner).run();
    return noStore({ deleted: true, conversation_id: conversationId });
  }

  return noStore({ error: "Método não permitido." }, 405);
}

/**
 * ============================================================
 * HANDLERS DE UPLOAD & CHAT
 * ============================================================
 */
async function handleUpload(request, env) {
  const identity = await requestIdentity(request, env, new URL(request.url).searchParams.get("mode") === "public");
  if (!identity) return jsonResponse(request, {error: "Identificação de upload necessária."}, 401);
  if (identity.user && request.headers.get("Origin") !== new URL(request.url).origin) {
    return jsonResponse(request, {error: "Origem não autorizada."}, 403);
  }
  if (Number(request.headers.get("Content-Length") || 0) > PROJECT_DOCUMENT_LIMIT + 65536) {
    return jsonResponse(request, {error: "PDF muito grande. Máximo: 15 MB."}, 413);
  }
  const limited = await consumePublicQuota(request, env, identity);
  if (limited) return limited;
  if (!env.OPENAI_API_KEY) {
    return jsonResponse(request, { error: "OPENAI_API_KEY não configurada." }, 500);
  }

  let formData;
  try {
    formData = await readMultipartBounded(request);
  } catch {
    return jsonResponse(request, { error: "FormData inválido." }, 400);
  }

  const file = formData.get("file");
  if (!(file instanceof File)) {
    return jsonResponse(request, { error: "Nenhum arquivo recebido." }, 400);
  }

  const fileName = file.name || "arquivo.pdf";
  if (file.size <= 0 || file.size > PROJECT_DOCUMENT_LIMIT) {
    return jsonResponse(request, {error: "Tamanho inválido. Máximo: 15 MB."}, 413);
  }
  if (file.type !== "application/pdf" && !fileName.toLowerCase().endsWith(".pdf")) {
    return jsonResponse(request, { error: "Somente arquivos PDF são permitidos." }, 400);
  }
  const signature = new TextDecoder().decode(await file.slice(0,5).arrayBuffer());
  if (signature !== "%PDF-") return jsonResponse(request, {error: "Conteúdo não é um PDF válido."}, 415);

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
  } catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível conectar à OpenAI durante o upload.",
      detail: error?.message || String(error)
    }, 502);
  }

  let data;
  try {
    data = await response.json();
  } catch {
    return jsonResponse(request, { error: "A OpenAI retornou resposta inválida durante o upload." }, 502);
  }

  if (!response.ok) {
    return jsonResponse(request, {
      error: "Não foi possível enviar o PDF.",
      detail: data?.error?.message || `HTTP ${response.status}`
    }, 502);
  }

  if (typeof data.id !== "string" || !/^file-[A-Za-z0-9_-]{1,150}$/.test(data.id)) {
    return jsonResponse(request, {error: "ID de arquivo inválido recebido da OpenAI."}, 502);
  }
  await ensureContentOwnershipSchema(env);
  await env.DB.prepare(`INSERT INTO edgeai_pdf_owners (file_id, owner_key, created_at) VALUES (?1, ?2, ?3)`)
    .bind(data.id, identity.key, new Date().toISOString()).run();
  return jsonResponse(request, { id: data.id, name: fileName });
}

async function handleChat(request, env, ctx) {
  if (!env.OPENAI_API_KEY) {
    return jsonResponse(request, { error: "OPENAI_API_KEY não configurada." }, 500);
  }
  if (!env.DB) {
    return jsonResponse(request, { error: "Banco D1 não configurado." }, 500);
  }

  try {
    await ensureDatabaseSchema(env);
  } catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível preparar o banco de dados.",
      detail: error?.message || String(error)
    }, 500);
  }

  let body;
  try {
    body = await readJsonBounded(request);
  } catch {
    return jsonResponse(request, { error: "JSON inválido." }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return jsonResponse(request, {error: "JSON deve ser um objeto."}, 400);
  }
  if (body.conversation_id !== undefined && !normalizeConversationId(body.conversation_id)) {
    return jsonResponse(request, {error: "Identificador de conversa inválido."}, 400);
  }
  if (body.message !== undefined && typeof body.message !== "string") {
    return jsonResponse(request, {error: "Mensagem inválida."}, 400);
  }
  if (body.file_ids !== undefined && (!Array.isArray(body.file_ids) || body.file_ids.length > 10 ||
      body.file_ids.some(id => typeof id !== "string" || !/^file-[A-Za-z0-9_-]{1,150}$/.test(id)))) {
    return jsonResponse(request, {error: "Lista de PDFs inválida."}, 400);
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
    return jsonResponse(request, {error: "Conversa não pertence ao chat público."}, 403);
  }
  const identity = await requestIdentity(request, env, !isPrivateScope);
  if (!identity) return jsonResponse(request, {error: "Identificação da sessão necessária."}, 401);
  const limited = await consumePublicQuota(request, env, identity);
  if (limited) return limited;
  await ensureContentOwnershipSchema(env);
  for (const fileId of fileIds) {
    const owned = await env.DB.prepare("SELECT file_id FROM edgeai_pdf_owners WHERE file_id = ?1 AND owner_key = ?2")
      .bind(fileId, identity.key).first();
    if (!owned) return jsonResponse(request, {error: "PDF não pertence a esta sessão."}, 403);
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
        return jsonResponse(request, {error: "Identificador de conversa já utilizado."}, 409);
      }
      await env.DB.prepare("INSERT OR IGNORE INTO edgeai_guest_conversations (conversation_id, owner_key) VALUES (?1, ?2)")
        .bind(conversationId, identity.key).run();
    }
    const owned = await env.DB.prepare("SELECT conversation_id FROM edgeai_guest_conversations WHERE conversation_id = ?1 AND owner_key = ?2")
      .bind(conversationId, identity.key).first();
    if (!owned) return jsonResponse(request, {error: "Conversa pública não pertence a este navegador. Inicie uma nova conversa."}, 403);
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
      if (!project) return jsonResponse(request, { error: "Acesso ao projeto negado." }, 403);
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
  } catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível carregar o histórico.",
      detail: error?.message || String(error)
    }, 500);
  }

  try {
    await upsertConversation(env, conversationId, userName);
    await saveMessage(
      env,
      conversationId,
      "user",
      message || "[PDF enviado sem texto adicional]",
      authenticatedUser?.id || null
    );
  } catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível salvar a conversa.",
      detail: error?.message || String(error)
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
  } catch (error) {
    return jsonResponse(request, {
      error: "Não foi possível conectar à OpenAI.",
      detail: error?.message || String(error)
    }, 502);
  }

  let openAIData;
  try {
    openAIData = await openAIResponse.json();
  } catch {
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
  } catch {
    return jsonResponse(request, { error: "A IA retornou resposta em formato inesperado." }, 502);
  }

  if (!result || typeof result.message !== "string") {
    return jsonResponse(request, { error: "Resposta estruturada inválida." }, 502);
  }

  try {
    await saveMessage(env, conversationId, "assistant", result.message);
    await upsertConversation(env, conversationId, userName);
  } catch (error) {
    console.error("ASSISTANT DATABASE ERROR:", error);
  }

  if (result.linkedin_action && result.linkedin_action.required === true) {
    const context = { conversationId, userName, message };
    let actionId = null;

    try {
      actionId = await saveLinkedInAction(env, context, result.linkedin_action);
    } catch (error) {
      console.error("LINKEDIN ACTION DATABASE ERROR:", error);
    }

    ctx.waitUntil(
      Promise.allSettled([
        notifyLinkedInUpdateByEmail(env, result.linkedin_action, context, actionId),
        notifyLinkedInUpdateBySlack(env, result.linkedin_action, context, actionId)
      ])
    );
  }

  return jsonResponse(request, {
    message: result.message,
    conversation_id: conversationId
  });
}

async function handleHealth(request, env) {
  let databaseStatus = "error";

  try {
    await ensureDatabaseSchema(env);
    await env.DB.prepare("SELECT COUNT(*) AS total FROM conversations").first();
    databaseStatus = "ok";
  } catch (error) {
    console.error("HEALTH DATABASE ERROR:", error);
  }

  const openAIStatus = env.OPENAI_API_KEY ? "configured" : "missing";
  const resendStatus = env.RESEND_API_KEY ? "configured" : "missing";
  const emailStatus = env.NOTIFICATION_EMAIL ? "configured" : "missing";
  const resendFromStatus = env.RESEND_FROM ? "configured" : "default";
  const slackStatus = env.SLACK_WEBHOOK_URL ? "configured" : "missing";

  const overallStatus = databaseStatus === "ok" && openAIStatus === "configured" ? "ok" : "error";

  return jsonResponse(
    request,
    {
      status: overallStatus,
      service: "EDGE AI Backend",
      version: BACKEND_VERSION,
      database: databaseStatus,
      openai_key: openAIStatus,
      resend_api_key: resendStatus,
      resend_from: resendFromStatus,
      notification_email: emailStatus,
      slack_webhook: slackStatus
    },
    overallStatus === "ok" ? 200 : 500
  );
}

/**
 * ============================================================
 * WORKER ENTRYPOINT
 * ============================================================
 */
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
          return jsonResponse(request, {error: "Origem não autorizada."}, 403);
        }
        if ((url.pathname === "/chat" || url.pathname === "/auth/firebase" || url.pathname === "/auth/login" || request.method === "PATCH") &&
            !/^application\/json(?:\s*;|$)/i.test(request.headers.get("Content-Type") || "")) {
          return jsonResponse(request, {error: "Content-Type deve ser application/json."}, 415);
        }
        if (!url.pathname.endsWith("/files") && url.pathname !== "/upload" &&
            Number(request.headers.get("Content-Length") || 0) > 131072) {
          return jsonResponse(request, {error: "Requisição muito grande."}, 413);
        }
      }

      // FRONTEND
      if (request.method === "GET" && (url.pathname === "/app" || url.pathname === "/app/")) {
        try {
          // Pin the reviewed frontend so the Worker deploy is independent of Pages propagation.
          const frontendResponse = await fetch("https://raw.githubusercontent.com/FredericoFahndrich/EdgeAI/a221f37579a407c639c8fc4dc2dc771ef7f681eb/index.html");
          if (!frontendResponse.ok) throw new Error("Frontend indisponível.");

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
        } catch {
          return jsonResponse(request, { error: "Não foi possível carregar o EDGE AI." }, 502);
        }
      }

      // SESSÃO
      if (request.method === "GET" && url.pathname === "/auth/session") {
        const user = await getAuthenticatedUser(request, env);
        const response = jsonResponse(request, {
          authenticated: Boolean(user),
          user: user || null
        });
        response.headers.set("Cache-Control", "no-store");
        return response;
      }

      if (request.method === 'POST' && url.pathname === '/auth/firebase') {
        return await exchangeFirebaseSession(request, env);
      }
      if (url.pathname === '/auth/login') {
        return jsonResponse(request,{error:'Use o login Firebase.',code:'firebase_required'},410);
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
          !await getAuthenticatedUser(request,env)) {
        return jsonResponse(request,{error:'Autenticação necessária.'},401);
      }

      // GESTÃO DE DOCUMENTOS DE PROJETO (R2)
      const documentResponse = await handleProjectDocuments(request, env, url);
      if (documentResponse) return documentResponse;

      // ROTAS PRIVADAS (PROJECTS & PERSONAL CONVERSATIONS)
      const privateResponse = await handlePrivateRoutes(request, env, url);
      if (privateResponse) return privateResponse;

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

    } catch (error) {
      console.error("UNHANDLED WORKER ERROR:", error);
      return jsonResponse(request, {
        error: "Erro interno no backend.",
        // Detalhes ficam apenas nos logs do servidor.
      }, 500);
    }
  }
};
