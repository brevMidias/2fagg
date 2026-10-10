# Phantom2FA

Serviço independente para códigos TOTP de seis dígitos, período de 30 segundos e HMAC-SHA1. Recebe somente segredo TOTP, UUID externo aleatório e token de acesso aleatório. O link `https://<worker>/c#<token>` funciona sem o PC depois da confirmação da API. Quem possui esse link pode consultar o código daquela entrada; nenhum PIN é pedido.

Publicado em 2026-10-10 em **https://2fagg.hostbrev0.workers.dev**, na Cloudflare Workers com D1. Criação, código TOTP, revogação e rejeição de operações atrasadas foram verificados remotamente com segredo sintético. Chaves administrativas e de cifragem ficam fora do Git; nenhum segredo de conta real foi usado nesse teste.

Página baseada na referência visual aprovada: [prévia desktop](docs/preview-desktop.png) e [prévia mobile](docs/preview-mobile.png), capturadas em Chromium com código sintético. O segredo não aparece na página.

## Ambiente e verificação

Node.js 24+, npm e PowerShell. A pasta é independente do PhantomDeck e pode virar repositório próprio. `package-lock.json` fixa as dependências; não há dependência de execução do outro projeto.

```powershell
npm ci
npm test
npm run typecheck
npm run check:deploy
npm run test:runtime
```

Testes de RFC 6238, Web Crypto, AES-GCM com identidade como AAD, nonce aleatório, SQL real em SQLite temporário, isolamento, idempotência/revisões, revogação, autenticação, validação, privacidade e comportamento da página com relógio controlado. O adaptador de teste executa o SQL verdadeiro; `test:runtime` também exercita o Worker empacotado em workerd/Miniflare com D1 local e dados sintéticos. Ambos são verificações locais, sem equivalente à validação remota do D1. Node 24.1 pode mostrar avisos de recursos experimentais de SQLite e TypeScript.

## Atualizar a publicação

O Worker `2fagg` e o banco `phantom2fa` já existem; `wrangler.jsonc` identifica os recursos publicados. O namespace de rate limit `726201` está reservado para este serviço. A primeira publicação foi feita pela integração autenticada da Cloudflare. Para atualizar por terminal, autentique o Wrangler e preserve as chaves existentes:

```powershell
npx wrangler login
npx wrangler d1 migrations apply phantom2fa --remote
npm run deploy
```

O gerador grava chaves independentes em `.keys/`, fora do Git, e não imprime seus valores. Recusa sobrescrever arquivos existentes. Proteja os arquivos por permissões do Windows e mantenha backup seguro, particularmente da chave de cifragem: perdê-la torna os registros existentes indecifráveis. Não altere `ENCRYPTION_KEY_B64` sem migração de todos os registros; versão de chave suportada atualmente: 1. A chave administrativa pode ser trocada em conjunto com a configuração do PhantomDeck.

Configure o backend do PhantomDeck com o endereço HTTPS confirmado e a mesma chave administrativa. Não use encurtadores de terceiros. Workers oferece subdomínio gratuito; domínio próprio curto é opcional. A existência de `/health` não prova que o D1 recebeu migrações: ele verifica apenas se os bindings e segredos têm configuração presente. Faça o primeiro smoke remoto com segredo sintético antes de sincronizar qualquer conta.

Para desenvolvimento local, aplique migrations com `npx wrangler d1 migrations apply phantom2fa --local`, configure `.dev.vars` com valores sintéticos e execute `npm run dev` manualmente. Essa configuração e `.wrangler/` são ignoradas pelo Git. Não copie banco, `.env`, tokens ou credenciais do PhantomDeck.

## Contrato de API

Toda resposta usa `Cache-Control: no-store`. Não há listagem de contas. Erros públicos de token inválido, ausente ou revogado são o mesmo `404` genérico. Erros não devolvem valores recebidos.

| Pedido | Autorização | Corpo / resposta |
| --- | --- | --- |
| `PUT /api/v1/entries/{uuid}` | `Bearer ADMIN_API_KEY` | JSON `{secret, access_token, revision}` → `{revision, status: "active"}` |
| `DELETE /api/v1/entries/{uuid}` | `Bearer ADMIN_API_KEY` | JSON `{revision}` → `{revision, status: "revoked"}` |
| `POST /api/public/code` | `Bearer access_token` | Sem corpo → `{code, remaining_seconds, server_time, valid_until}` |
| `GET /c` | Nenhuma | Página lê o token do fragmento local e envia em Authorization |
| `GET /health` | Nenhuma | `{status: "ok"}` se configurado, senão `503` |

`server_time` e `valid_until` são segundos inteiros Unix UTC. `remaining_seconds` está entre 1 e 30. UUID é v4 canônico em minúsculas e deve ser independente do ID local. `access_token` é base64url canônico de 16 bytes aleatórios: 22 caracteres, sem padding (último caractere A/Q/g/w). `secret` é Base32 canônico em maiúsculas, sem padding, de 16 a 128 caracteres e 10 a 80 bytes decodificados. `revision` é inteiro positivo até `Number.MAX_SAFE_INTEGER`.

Rotação usa o mesmo `PUT`, mesmo segredo e novo token, com revisão maior. Não existe rota `/rotate`: a revisão identifica a operação. Repetir exatamente a mesma revisão/corpo é idempotente; mesmo número com dados diferentes ou revisão menor devolve `409`. O SQL faz comparação e atualização atômicas. Revogação mantém tombstone e elimina segredo cifrado/hash de token; nunca remover tombstones sem um mecanismo substituto contra operações atrasadas. Uma nova revisão maior pode reativar explicitamente uma entrada revogada. Token já atribuído a outra entrada produz `409`. A fila local deve serializar operações e preservar o corpo de cada revisão até confirmar.

## Proteções e limites

- Segredo cifrado AES-GCM com chave de 32 bytes, nonce aleatório de 12 bytes por escrita e UUID como AAD. Banco guarda apenas hash SHA256 do token e digest da operação; não guarda token/segredo em texto puro. Ao revogar, mantém somente identificador, revisão e digest/timestamps.
- Autorização administrativa compara hashes de tamanho fixo. Campos desconhecidos, corpo maior que 2 KiB, identificadores inválidos, secret/token malformados e revisões inválidas são recusados. SQL parametrizado. Falha do banco, cifra ou configuração devolve `503` sem detalhes.
- Rate limiter nativo do Worker: 30 pedidos/minuto por IP e canal público/admin, antes de leitura/escrita no D1. IP entra no limiter como hash. Não há gravação de rate limit no banco. Esse limite é local ao ponto de presença Cloudflare e aproximado; não é cota global nem impede abuso distribuído. Não habilitar analytics, logs de corpo ou captura de cabeçalhos de autorização. Observability está desabilitado, sem terceiros na página.
- Página envia CSP restritiva, `no-store`, `noindex` e `Referrer-Policy: no-referrer`; o fragmento não é enviado pelo navegador no GET. Nenhum segredo aparece no HTML. Copia somente código válido; pausa consultas na aba oculta, renova ao voltar, usa relógio monotônico ajustado ao prazo do servidor e apaga código vencido mesmo quando falha a rede.

Em 2026-10-10, o [Workers Free](https://developers.cloudflare.com/workers/platform/limits/) informa 100.000 pedidos/dia; o [D1 Free](https://developers.cloudflare.com/d1/platform/pricing/) inclui 5 milhões de linhas lidas/dia, 100.000 escritas/dia e 5 GB totais. A [API de rate limit](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/) aplica contadores por localização, não globalmente. Limites e condições podem mudar. Consultas de código usam índice único; a página ativa normalmente faz aproximadamente 2 consultas/minuto. Limites do plano e indisponibilidade da rede podem bloquear consultas; não há garantia de SLA nem promessa de disponibilidade ilimitada. Retentativas da página espaçam falhas em 5 segundos.
