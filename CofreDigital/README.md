# Cofre Digital (Digital Vault) — INF1416, Trabalho 3

Aplicação Java SE (Swing + SQLite) que protege uma pasta segura com controle de
integridade, autenticidade, sigilo e acesso, com autenticação bifator (senha pessoal
por teclado virtual sobrecarregado + TOTP do Google Authenticator) e registro de
auditoria visualizado por um programa separado (logView).

## Requisitos

- JDK 17 ou superior (testado com OpenJDK 21).
- Bibliotecas em `lib/` (já incluídas):
  - `bcprov-jdk18on-1.77.jar` — BouncyCastle (`OpenBSDBCrypt` para o bcrypt 2y).
  - `sqlite-jdbc-3.46.1.3.jar` — driver JDBC do SQLite.

## Compilação

```sh
./build.sh          # Linux / macOS
build.bat           # Windows
```

Gera `dist/CofreDigital.jar`, `dist/LogView.jar` e `dist/lib/`.

## Execução

```sh
cd dist
java -jar CofreDigital.jar              # usa ./cofre.db (criado na 1ª execução)
java -jar CofreDigital.jar outro.db     # banco alternativo

java -jar LogView.jar <caminho_da_chave_privada_do_admin> [cofre.db]
```

O logView lê a frase secreta pelo console, sem eco (`System.console().readPassword`).
Rode-o num terminal de verdade; dentro de uma IDE não há console e a frase é lida
da entrada padrão (com aviso).

## Roteiro de teste com o Pacote-T3

| Usuário | Certificado / chave | Frase secreta |
|---|---|---|
| admin@inf1416.puc-rio.br | `Keys/admin-x509.crt` / `Keys/admin-pkcs8-aes.key` | `admin` |
| user01@inf1416.puc-rio.br | `Keys/user01-x509.crt` / `Keys/user01-pkcs8-aes.key` | `user01` |
| user02@inf1416.puc-rio.br | `Keys/user02-x509.crt` / `Keys/user02-pkcs8-aes.key` | `user02` |

1. 1ª execução: cadastre o admin (grupo fixo Administrador) e escolha uma senha
   pessoal (ex.: `13572468`). Cadastre a chave BASE32 exibida no Google Authenticator.
2. Faça login como admin e cadastre user01 e user02 (grupo Usuário).
3. Na consulta, informe a pasta `Files` do pacote e a frase secreta do usuário logado.
   Resultado esperado:
   - admin vê `teste00.docx` (dono);
   - user01 vê `teste01.docx` (dono) e `teste02.docx` (compartilhado, `XXYYZZ22.1.shr`);
   - user02 vê `teste01.docx` (grupo `usuario`) e `teste02.docx` (dono).
4. Duplo clique no arquivo: ele é decriptado, verificado e gravado com o nome
   secreto na própria pasta.

## Organização do código

```
src/cofre/
  CofreDigital.java      ponto de entrada, partida do sistema, navegação, Tela Principal e Tela de Saída
  TelaAutenticacao.java  etapas 1 (login), 2 (teclado virtual) e 3 (TOTP)
  TelaCadastro.java      Tela de Cadastro (também usada na partida para o admin)
  TelaConsulta.java      Tela de Consultar Pasta de Arquivos Secretos
  Ui.java                cabeçalho / corpo 1 / corpo 2 e utilidades visuais
  Sessao.java            estado em memória (frase e chave do admin, usuário logado)
  AuthService.java       regras das três etapas, contagem de erros e bloqueio
  CadastroService.java   crítica dos campos, validação da chave privada, gravação
  CofreService.java      index/share, política de acesso, decriptação de arquivos
  CryptoUtil.java        AES/SHA1PRNG, RSA (envelope), SHA1withRSA, bcrypt, X.509
  TOTP.java              RFC 6238/4226 (só Mac, SecretKeySpec, Date e Base32)
  Base32.java            classe fornecida no enunciado
  Database.java          esquema e acesso ao SQLite
  Mensagens.java         Tabela de Mensagens de Registro
  Registrador.java       gravação na tabela Registros
src/logview/LogView.java programa de auditoria (JAR separado)
test/TesteIntegracao.java teste automatizado sem GUI (45 verificações)
```

## Banco de dados (SQLite)

| Tabela | Campos principais |
|---|---|
| `Grupos` | `GID`, `nome` (`administrador` = 1, `usuario` = 2, iguais aos usados no index) |
| `Usuarios` | `UID`, `nome`, `email` (login name, único), `GID`, `senha` (bcrypt, 60 caracteres), `token_key` (BASE32 do segredo TOTP cifrado em AES), `KID`, `num_acessos`, `num_consultas`, `erros_senha`, `erros_token`, `bloqueado_ate` |
| `Chaveiro` | `KID`, `UID`, `certificado` (PEM), `chave_privada` (binário cifrado, como recebido) |
| `Mensagens` | `MID`, `texto` |
| `Registros` | `RID`, `data_hora`, `MID`, `UID`, `login_name` (só quando não identificado, 2005), `arquivo` |

A tabela `Registros` nunca guarda o texto das mensagens: o logView monta o texto
juntando `Mensagens` e substituindo `<login_name>` e `<arq_name>`.

## Decisões de projeto

- **Senha pessoal:** bcrypt `$2y$08$` via `OpenBSDBCrypt.generate`/`checkPassword`.
  Regra de cadastro: 8 a 10 dígitos, sem dígitos iguais em sequência (ex.: `11`).
- **Verificação pelo teclado sobrecarregado:** cada toque informa um par de dígitos,
  então existem 2ⁿ candidatos. Todos são testados contra o hash (em paralelo),
  descartando os que violam a regra de cadastro. A operação roda em segundo plano
  (`SwingWorker`) e leva alguns segundos para 10 dígitos.
- **Segredo TOTP:** 20 bytes de `SecureRandom`, codificados em BASE32 e cifrados com
  AES/ECB/PKCS5 usando uma chave de 256 bits gerada por SHA1PRNG a partir da senha
  pessoal. A senha encontrada na etapa 2 fica em memória só até o fim da etapa 3.
- **Validação da chave privada:** assinatura SHA1withRSA de 10240 bytes aleatórios,
  verificada com a chave pública do certificado. É usada no cadastro, na partida e no
  botão Listar. O logView usa 2048 bytes e aceita apenas o certificado de um usuário
  do grupo Administrador.
- **Partida:** o "administrador do sistema" é o primeiro admin cadastrado. Sua frase
  secreta e sua chave privada ficam em memória para abrir os envelopes de `index` e
  `share`. São apagadas (`Arrays.fill`) no encerramento do sistema.
- **Bloqueio:** 3 erros consecutivos (de senha ou de token) bloqueiam por 2 minutos.
  Contadores e bloqueio ficam no banco, então reiniciar o programa não zera o bloqueio.
- **Total de acessos:** soma 1 a cada autenticação completa.
  **Total de consultas:** soma 1 a cada listagem bem-sucedida.
- **Validação da frase no Listar:** registra 6006/6007, pois o enunciado manda
  validar "da mesma forma que no cadastro" e não define códigos próprios.
- **Política de acesso:** o usuário vê o arquivo se for o dono, se o grupo do arquivo
  for o seu, ou se houver linha no `share` com o seu login. O envelope usado é o
  `.env` (dono) ou o `.N.shr` (compartilhamento).

## Limitações conhecidas

- **Acesso só pelo grupo:** o arquivo aparece na lista, mas o `.env` foi gerado para a
  chave pública do dono. Se não houver `.shr` para o usuário, a decriptação falha
  (registro 7020) e o motivo é mostrado. Com o pacote, isso acontece com
  user02 → `teste01.docx`.
- **QR Code:** não é gerado (o enunciado diz que é opcional). A chave BASE32 e a URI
  `otpauth://` são exibidas para cadastro manual no Google Authenticator, com botão
  "Copiar chave".

## Teste automatizado

```sh
mkdir -p test-out
javac -encoding UTF-8 -d out -cp "lib/*" $(find src -name "*.java")
javac -encoding UTF-8 -d test-out -cp "out:lib/*" test/TesteIntegracao.java
java -cp "out:lib/*:test-out" TesteIntegracao <pasta_do_Pacote-T3>
```

Cobre: vetores do RFC 6238, crítica de senha, códigos 6004–6007, unicidade do login,
etapas 1–3, bloqueio, listagem por usuário, decriptação (dono e compartilhado), falha
de envelope por grupo e adulteração de `index.asd` e de `.asd` de arquivo
(7008/7021). No Windows, troque `:` por `;` no classpath.
