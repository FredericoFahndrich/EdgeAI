# Usuários e acessos por e-mail

O painel continua administrando vínculos antigos e projetos. Novas contas verificadas entram no espaço pessoal automaticamente, sem memberships. Consulte [Cadastro verificado](verified-registration.md) para o comportamento atual e o corte em produção; a aprovação abaixo se aplica ao vínculo explícito de membros antigos.

## Escolha

O menu **Configurações · usuários e acessos** é a forma recomendada para operação diária. O D1 permanece disponível para manutenção e recuperação administrativa. A autorização é feita no Worker a cada requisição, pela identidade D1 `usr_frederico`, já vinculada a um UID Firebase aprovado; esconder o botão não é a proteção de segurança.

## Fluxo de aprovação

1. Frederico abre Configurações e escolhe explicitamente um usuário existente ou cria um novo usuário.
2. Aprova o e-mail exato. Para um usuário existente, o histórico e os acessos atuais permanecem ligados ao mesmo `user_id`. Não se procura usuário por nome nem se presume identidade por e-mail não aprovado.
3. O usuário faz login Google ou e-mail/senha no Firebase. No caso de senha, precisa verificar o e-mail pelo link enviado pelo Firebase; a tela oferece enviar a verificação e reconectar.
4. O Worker verifica assinatura e claims do ID token. Somente `email_verified: true` e e-mail previamente aprovado podem criar o vínculo UID → usuário D1 escolhido pelo administrador. Não se aceitam e-mail/UID fornecidos separadamente pelo cliente.
5. A aprovação é consumida pelo primeiro UID elegível. Um UID diferente não pode assumir o usuário pelo mesmo e-mail, e nenhum vínculo existente ou revogado é substituído automaticamente.

Para um membro já existente, selecionar o registro correto na lista, aprovar o e-mail confirmado pelo administrador e preservar seus projetos atuais. Não é necessário recolher o UID manualmente depois desse fluxo.

Novos usuários recebem acesso à conta pessoal após a aprovação e login verificado; começam sem projeto. O administrador define os projetos e os papéis `editor` ou `owner` separadamente. Uma aprovação de e-mail **não envia convite** nem cria senha Firebase. O próprio usuário cria sua conta ou entra com Google.

## Operações do painel

- Listar usuários, e-mail aprovado, situação do vínculo, atividade e permissões por projeto.
- Aprovar e-mail para novo usuário ou usuário existente ainda sem vínculo/aprovação.
- Conceder ou remover acesso a um projeto; preservar conversas e documentos.
- Suspender usuário, revogando suas sessões; reativar exige novo login e não revalida cookies revogados.
- Revogar identidade e aprovação. Não existe reatribuição automática por outro e-mail/UID: correções de identidade exigem procedimento administrativo explícito no D1.
- Proteger o administrador contra remoção de seu próprio acesso pelo painel.
- Registrar aprovação de e-mail, mudanças de atividade, identidade e membership em `edgeai_admin_audit`, na mesma transação da alteração.

O painel gerencia contas e acessos do EDGE AI; não gerencia contas Google/Firebase, senhas ou conteúdo editorial do site. A lista não retorna hashes de acesso, cookies ou tokens. E-mails e UIDs reais não estão nos arquivos públicos deste PR.

## Banco e implantação

Aplicar `backend/migrations/0002_email_access_admin.sql` após 0001, antes de publicar este Worker. A migration cria as tabelas de aprovações e auditoria sem alterar vínculos ou memberships existentes. Ela não foi aplicada remotamente nesta etapa.

Administração direta pelo D1 segue as mesmas regras: aprovar o e-mail exato para um `user_id` confirmado, registrar responsável/data e manter unicidade de e-mail e usuário. Não copiar tokens nem editar hashes. Os nomes de tabelas e restrições estão na migration; não executar SQL com placeholders literais.

A decisão anterior de preparar os demais membros antes do corte continua válida. Agora a preparação pode usar e-mails aprovados, sem exigir UIDs prévios. Falta concluir as aprovações necessárias e executar validação real antes da publicação. O e-mail de um membro informado pelo titular não foi inserido automaticamente no D1.

## Validação

59 cenários backend e 10 cenários UI passam localmente. Incluem negação para não administradores, token de e-mail não verificado, e-mail não aprovado, segundo UID, preservação de membership existente, novo usuário sem projetos, concessão/remoção imediata de projeto, auditoria, suspensão, revogação e proteção do administrador. Chrome com serviços simulados valida formulário e estados do painel. Ainda não é validação de produção.

Referências oficiais: https://firebase.google.com/docs/auth/admin/verify-id-tokens e https://firebase.google.com/docs/auth/web/manage-users .
