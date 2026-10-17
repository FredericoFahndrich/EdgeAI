# Integração Firebase → Worker → D1 (proposta 3.0.0)

**Registro histórico da primeira proposta.** O comportamento atual de cadastro pessoal, a migration 0003, as permissões de owners e o roteiro de publicação/rollback estão em [Cadastro verificado](verified-registration.md). O restante deste documento descreve a inspeção e a proposta originais.

## Inspeção realizada

- Conector GitHub: `main` contém HTML e imagens; não havia Worker nem migrations.
- Código copiado do editor ativo Cloudflare e comparado com a cópia local após normalizar CRLF: SHA-256 `ca44a6fe5c031879b6b10ca5cd24f749954a42689e982647978f5d8d1f7bcd2b`.
- Banco vinculado `edgeai-db`, binding `DB`; R2 `FILES_BUCKET`. Inspeção somente leitura de `sqlite_master` e membros.
- D1 contém `users`, `user_sessions`, `auth_login_limits`, `projects`, `project_members`, `conversations`, `messages` e tabelas de documentos/ownership. Não havia tabela Firebase nem registro de migrations.
- Projeto Solar: quatro membros ativos, um owner e três editors. Nenhuma associação ou dado alterado.
- Console Firebase `edgeai-auth`: inicialmente sem usuários; após login realizado pelo titular, conta Google e UID informados foram conferidos no projeto correto. O UID real fica fora deste repositório público.
- Domínio `edgeai-backend.frederico-fahndrich.workers.dev` confirmado na lista Firebase de domínios autorizados.
- Acesso ao Cloudflare disponível pelo navegador. Não há bloqueio de acesso ao painel.

## Contrato de autenticação

Atualização: o gerenciamento administrativo por e-mail e projeto está descrito em [Usuários e acessos](email-access-admin.md). Antes de publicar esta revisão, aplicar também a migration 0002. O painel prepara aprovações por e-mail verificado sem exigir coleta prévia de UIDs.

`POST /auth/firebase` recebe `{idToken}` apenas na origem do Worker. Verifica assinatura RS256 com chaves públicas fixas Google, `kid`, issuer, audience `edgeai-auth`, subject, expiração, iat, auth_time e provedor Google/password. Tokens não são gravados nem registrados.

Somente o par projeto/UID previamente aprovado em `edgeai_firebase_identities` pode gerar sessão. Nenhum nome, e-mail, parâmetro `user_id` ou cadastro Firebase concede identidade D1. Usuários precisam continuar ativos em `users`. Não existe endpoint público para aprovar vínculos.

A sessão aleatória é armazenada como SHA-256 em `user_sessions`, ligada ao UID em `edgeai_firebase_sessions`, e expira no máximo junto com o ID token. Cookie HttpOnly/Secure/SameSite=Lax. Cada consulta revalida usuário ativo e vínculo não revogado. Logout revoga a sessão no D1. Revogação administrativa do vínculo bloqueia sessões existentes imediatamente.

**Limitação explícita:** este verificador de assinatura não consulta revogação/desativação no Firebase Admin. Um ID token já emitido pode continuar válido até `exp` (normalmente até uma hora). Para bloqueio imediato, revogar o vínculo D1 ou desativar `users.is_active`. Não alegar revogação global instantânea do Firebase.

Login legado `/auth/login` retorna 410. Sessões legadas deixam de ser aceitas no corte; os registros são preservados. `/chat`, `/upload`, `/projects/*` e `/me/*` exigem sessão backend. O antigo modo `public` cria conversa pessoal do usuário autenticado; históricos guest não são adotados. PDFs guest antigos também não são adotados. `project_members` permanece a autoridade de acesso a projetos.

## Interface

GitHub Pages direciona para `/app` no Worker, evitando dependência de cookies de terceiros. `/app` mantém base de assets no Pages. **Confirmar o domínio `edgeai-backend.frederico-fahndrich.workers.dev` em Firebase Authentication → Settings → Authorized domains antes do corte.**

O observador Firebase troca token por sessão e confirma `/auth/session` antes de abrir chat. Logout limpa dados na interface e revoga backend antes de sair do Firebase. HTTP 401 bloqueia a interface; Reconectar permite repetir a validação. Trocas de conta descartam respostas atrasadas. Recuperação de senha usa Firebase com resposta genérica; cadastro cria somente conta Firebase e fica aguardando aprovação de acesso. Não cria usuário D1 ou associação a projeto.

## Aprovação de identidade (não executar com placeholders)

1. Usuário realiza login real no Firebase e informa conclusão; administrador confere UID no projeto correto.
2. Administrador confirma explicitamente o par UID → user_id existente. E-mail/nome ajudam na conferência humana, nunca são prova automática.
3. Registrar aprovação e data. Inserir um único vínculo por usuário/UID com SQL parametrizado, após a migration. Não usar UPDATE ou UPSERT para substituir silenciosamente vínculo existente.
4. Revisar todos os usuários que precisam manter acesso no corte. Os quatro membros atuais perderão sessões legadas; vincular somente os UIDs comprovados e aprovados. Planejar janela de corte caso nem todos estejam prontos.

Modelo parametrizado, destinado ao administrador:

```sql
INSERT INTO edgeai_firebase_identities
 (firebase_project,firebase_uid,user_id,approved_by,approved_at)
SELECT 'edgeai-auth',?1,id,?3,?4 FROM users WHERE id=?2 AND is_active=1;
```

Exigir exatamente uma linha inserida; verificar o vínculo e a contagem de membros após a operação. Nunca publicar UIDs reais ou tokens no repositório público.

## Ordem de publicação e rollback

1. Guardar Worker ativo e obter bookmark atual D1; registrar contagens de conversas, mensagens, documentos, usuários e membros. Não reutilizar bookmark antigo.
2. Aplicar `backend/migrations/0001_firebase_identity.sql` (aditiva e idempotente). Conferir esquema e registro `0001_firebase_identity`.
3. Aprovar e inserir vínculos exatos. Conferir domínio Firebase e testar Google/e-mail no domínio `/app`.
4. Preparar janela coordenada: publicar Worker 3.0.0 com frontend fixado por SHA na mesma proposta. `/app` usa um HTML imutável do GitHub, evitando combinar backend novo com Pages 5B.2 durante propagação. Após validar `/app`, publicar o frontend/redirect no Pages. O Worker 3.0.0 desativa sessões antigas: usuários ainda sem UID aprovado precisam de preparação antes do corte.
5. Testar produção: duas contas reais vinculadas (owner/editor), uma não aprovada e uma vinculada sem membership; login → sessão → lista → conversa → mensagem → upload → download/hash → reload → logout. Confirmar 401 anônimo, 403 não membro, isolamento pessoal em ambas as direções e recusa de PDF estrangeiro. Testar modo public por chamada direta com e sem sessão.
6. Confirmar conteúdo anterior do Projeto Solar e preservação de `project_members`. Não enviar solicitações de LinkedIn nos testes, evitando efeitos externos.

Rollback coordenado: restaurar Worker `4e512dd0` e frontend `cfc139d` (ambos), mantendo tabelas aditivas. Isso restaura o modelo antigo, inclusive acesso guest; documentar a regressão de segurança. Não restaurar D1 inteiro nem excluir dados sem autorização específica.

## Testes reproduzíveis

Node.js 24, sem dependências externas:

```text
node backend/test-integration.mjs
node test-ui.mjs
```

59 cenários backend aprovados: RSA real local com chaves de teste, SQLite real/adaptador D1, OpenAI/R2 simulados, administração de acessos e aprovação por e-mail verificado. 10 cenários de coordenação UI aprovados em VM com DOM/HTTP simulados, incluindo inicialização do SDK, renovação sem perder rascunho, troca de conta concorrente, limpeza do painel e falha no logout. Sintaxe dos scripts clássicos verificada.

Foi executada também uma prévia local no Chrome, com SDK/HTTP simulados: login, desbloqueio após sessão confirmada, lista de espaços, mensagem/resposta e logout. Esses testes não equivalem a validação real do Worker publicado.

Após confirmação explícita do titular, a migration 0001 foi aplicada no D1 remoto e um vínculo do titular com o usuário D1 existente foi inserido e consultado novamente. O UID real fica fora deste repositório. O vínculo mantém a propriedade existente do Projeto Solar. O titular escolheu preparar também os outros três UIDs antes do corte: Worker e Pages continuam nas versões anteriores até concluir essa preparação. Não houve deploy ou merge.

Referência: https://firebase.google.com/docs/auth/admin/verify-id-tokens
