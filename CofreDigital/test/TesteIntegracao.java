import cofre.*;

import java.lang.reflect.Method;
import java.nio.file.*;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Teste de integração sem interface gráfica, usando o Pacote-T3.
 *
 * Uso: java -cp "out:lib/*:test-out" TesteIntegracao <pasta_Pacote-T3>
 */
public class TesteIntegracao {

    static int ok = 0, falhas = 0;

    static void check(String nome, boolean cond) {
        if (cond) { ok++; System.out.println("  [OK]    " + nome); }
        else { falhas++; System.out.println("  [FALHA] " + nome); }
    }

    /** Simula o teclado virtual: cada dígito da senha cai num botão com outro dígito aleatório. */
    static List<int[]> simularTeclado(String senha, Random r) {
        List<int[]> pares = new ArrayList<>();
        for (char c : senha.toCharArray()) {
            int d = c - '0';
            int outro;
            do { outro = r.nextInt(10); } while (outro == d);
            pares.add(r.nextBoolean() ? new int[] {d, outro} : new int[] {outro, d});
        }
        return pares;
    }

    static String gerarTotp(String base32) throws Exception {
        TOTP t = new TOTP(base32, 30);
        return t.generateCode();
    }

    public static void main(String[] args) throws Exception {
        Path pacote = Paths.get(args[0]);
        Path keys = pacote.resolve("Keys"), files = pacote.resolve("Files");
        Path tmp = Files.createTempDirectory("cofre-teste");
        Path dbFile = tmp.resolve("teste.db");
        Random rnd = new Random(42);

        System.out.println("== TOTP (vetores do RFC 6238, SHA1) ==");
        String rfcSecret = new Base32(Base32.Alphabet.BASE32, false, false)
                .toString("12345678901234567890".getBytes("US-ASCII"));
        TOTP rfc = new TOTP(rfcSecret, 30);
        Method m = TOTP.class.getDeclaredMethod("TOTPCode", long.class);
        m.setAccessible(true);
        check("T=59s -> 287082", "287082".equals(m.invoke(rfc, 59L / 30)));
        check("T=1111111109s -> 081804", "081804".equals(m.invoke(rfc, 1111111109L / 30)));
        check("T=1234567890s -> 005924", "005924".equals(m.invoke(rfc, 1234567890L / 30)));
        check("T=2000000000s -> 279037", "279037".equals(m.invoke(rfc, 2000000000L / 30)));
        check("validateCode aceita código atual", rfc.validateCode(rfc.generateCode()));
        check("validateCode recusa código inválido", !rfc.validateCode("12345a"));

        Database db = new Database(dbFile.toString());
        Sessao s = new Sessao(db);

        System.out.println("== Cadastro ==");
        check("senha curta recusada", CadastroService.validarSenha("1357246".toCharArray(), "1357246".toCharArray()) != null);
        check("senha com repetição recusada", CadastroService.validarSenha("13572446".toCharArray(), "13572446".toCharArray()) != null);
        check("senha com letra recusada", CadastroService.validarSenha("1357246a".toCharArray(), "1357246a".toCharArray()) != null);
        check("confirmação diferente recusada", CadastroService.validarSenha("13572468".toCharArray(), "13572469".toCharArray()) != null);
        check("senha válida aceita", CadastroService.validarSenha("13572468".toCharArray(), "13572468".toCharArray()) == null);

        // admin na partida
        CadastroService.Preparado pa = s.cadastro.preparar(keys.resolve("admin-x509.crt").toString(),
                keys.resolve("admin-pkcs8-aes.key").toString(), "admin".toCharArray(), null);
        check("nome/login extraídos do Sujeito", "Administrator".equals(pa.nome) && "admin@inf1416.puc-rio.br".equals(pa.email));
        CadastroService.Efetivado ea = s.cadastro.efetivar(pa, Database.GID_ADMINISTRADOR, "13572468".toCharArray());
        check("segredo TOTP BASE32 com 32 caracteres", ea.segredoBase32.length() == 32);
        Database.Usuario admin = db.findUsuarioByEmail("admin@inf1416.puc-rio.br");
        check("hash bcrypt $2y$08$ com 60 caracteres", admin.senhaHash.startsWith("$2y$08$") && admin.senhaHash.length() == 60);
        check("KID associado ao usuário", admin.kid != null && db.findChaveiro(admin.kid).uid == admin.uid);
        check("certificado guardado em PEM", db.findChaveiro(admin.kid).certificadoPem.startsWith("-----BEGIN CERTIFICATE-----"));

        PrivateKey adminPk = CadastroService.chavePrivadaDoUsuario(db, admin, "admin".toCharArray(), 10240);
        X509Certificate adminCert = CadastroService.certificadoDoUsuario(db, admin);
        s.definirAdministrador("admin".toCharArray(), adminPk, adminCert);

        String[] erros = new String[1];
        try {
            s.cadastro.preparar(keys.resolve("user01-x509.crt").toString(), keys.resolve("user01-pkcs8-aes.key").toString(),
                    "errada".toCharArray(), admin);
        } catch (CadastroService.CadastroException e) { erros[0] = "" + e.mid; }
        check("frase secreta errada -> 6006", "6006".equals(erros[0]));
        try {
            s.cadastro.preparar(keys.resolve("user01-x509.crt").toString(), keys.resolve("admin-pkcs8-aes.key").toString(),
                    "admin".toCharArray(), admin);
        } catch (CadastroService.CadastroException e) { erros[0] = "" + e.mid; }
        check("chave de outro dono -> 6007", "6007".equals(erros[0]));
        try {
            s.cadastro.preparar("/nao/existe.crt", keys.resolve("user01-pkcs8-aes.key").toString(), "user01".toCharArray(), admin);
        } catch (CadastroService.CadastroException e) { erros[0] = "" + e.mid; }
        check("certificado inexistente -> 6004", "6004".equals(erros[0]));
        try {
            s.cadastro.preparar(keys.resolve("user01-x509.crt").toString(), "/nao/existe.key", "user01".toCharArray(), admin);
        } catch (CadastroService.CadastroException e) { erros[0] = "" + e.mid; }
        check("chave inexistente -> 6005", "6005".equals(erros[0]));

        CadastroService.Preparado p1 = s.cadastro.preparar(keys.resolve("user01-x509.crt").toString(),
                keys.resolve("user01-pkcs8-aes.key").toString(), "user01".toCharArray(), admin);
        CadastroService.Efetivado e1 = s.cadastro.efetivar(p1, Database.GID_USUARIO, "2468013579".toCharArray());
        CadastroService.Preparado p2 = s.cadastro.preparar(keys.resolve("user02-x509.crt").toString(),
                keys.resolve("user02-pkcs8-aes.key").toString(), "user02".toCharArray(), admin);
        CadastroService.Efetivado e2 = s.cadastro.efetivar(p2, Database.GID_USUARIO, "975310864".toCharArray());
        check("3 usuários cadastrados", db.countUsuarios() == 3);
        boolean dup = false;
        try { s.cadastro.efetivar(p1, Database.GID_USUARIO, "2468013579".toCharArray()); }
        catch (CadastroService.CadastroException ex) { dup = true; }
        check("login name duplicado recusado", dup);

        System.out.println("== Autenticação ==");
        check("etapa 1: e-mail inválido", s.auth.verificarLogin("naoemail").resultado == AuthService.ResultadoEtapa1.INVALIDO);
        check("etapa 1: não identificado", s.auth.verificarLogin("x@inf1416.puc-rio.br").resultado == AuthService.ResultadoEtapa1.NAO_IDENTIFICADO);
        AuthService.Etapa1 r1 = s.auth.verificarLogin("user01@inf1416.puc-rio.br");
        check("etapa 1: liberado", r1.resultado == AuthService.ResultadoEtapa1.LIBERADO);
        Database.Usuario u1 = r1.usuario;

        long t0 = System.currentTimeMillis();
        char[] senha = AuthService.encontrarSenha(u1.senhaHash, simularTeclado("2468013579", rnd));
        long dt = System.currentTimeMillis() - t0;
        check("etapa 2: senha de 10 dígitos encontrada pelo teclado sobrecarregado (" + dt + " ms)",
                senha != null && new String(senha).equals("2468013579"));
        check("etapa 2: senha errada não encontrada",
                AuthService.encontrarSenha(u1.senhaHash, simularTeclado("2468013570", rnd)) == null);

        String seg = AuthService.decriptarSegredoTotp(u1.tokenKeyCifrada, senha);
        check("etapa 3: segredo TOTP decriptado com a senha", seg.equals(e1.segredoBase32));
        check("etapa 3: token correto aceito", AuthService.validarToken(u1.tokenKeyCifrada, senha, gerarTotp(seg)));
        check("etapa 3: token errado recusado", !AuthService.validarToken(u1.tokenKeyCifrada, senha, "000000")
                || gerarTotp(seg).equals("000000"));
        s.auth.registrarTokenOk(u1);
        check("total de acessos incrementado", db.findUsuarioByUid(u1.uid).numAcessos == 1);

        // Bloqueio por 3 erros de senha (user02)
        Database.Usuario u2 = s.auth.verificarLogin("user02@inf1416.puc-rio.br").usuario;
        s.auth.registrarErroSenha(u2);
        s.auth.registrarErroSenha(u2);
        AuthService.ResultadoEtapa2 b = s.auth.registrarErroSenha(u2);
        check("3º erro de senha bloqueia", b == AuthService.ResultadoEtapa2.BLOQUEADO);
        check("etapa 1: bloqueado", s.auth.verificarLogin("user02@inf1416.puc-rio.br").resultado == AuthService.ResultadoEtapa1.BLOQUEADO);
        long resta = db.findUsuarioByUid(u2.uid).bloqueadoAte - System.currentTimeMillis();
        check("bloqueio de ~2 minutos", resta > 110_000 && resta <= 120_000);
        db.bloquear(u2.uid, 0); // libera para o restante do teste

        System.out.println("== Consulta da pasta segura ==");
        Path pasta = tmp.resolve("pasta");
        Files.createDirectories(pasta);
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(files)) {
            for (Path f : ds) Files.copy(f, pasta.resolve(f.getFileName()));
        }
        boolean inval = false;
        try { s.cofre.listar(tmp.resolve("nada").toString(), u1, adminPk, adminCert); }
        catch (CofreService.CofreException ex) { inval = true; }
        check("pasta inválida -> erro (7004)", inval);

        Map<String, CofreService.Listagem> lst = new LinkedHashMap<>();
        for (String login : new String[] {"admin@inf1416.puc-rio.br", "user01@inf1416.puc-rio.br", "user02@inf1416.puc-rio.br"}) {
            Database.Usuario u = db.findUsuarioByEmail(login);
            CofreService.Listagem l = s.cofre.listar(pasta.toString(), u, adminPk, adminCert);
            lst.put(login, l);
            StringBuilder sb = new StringBuilder();
            for (CofreService.Entrada e : l.entradas) sb.append(e.nomeSecreto).append('(').append(e.acesso).append(") ");
            System.out.println("    " + login + ": " + sb);
        }
        check("admin vê apenas teste00 (dono)", nomes(lst.get("admin@inf1416.puc-rio.br")).equals(List.of("teste00.docx")));
        check("user01 vê teste01 (dono) e teste02 (compartilhado)",
                nomes(lst.get("user01@inf1416.puc-rio.br")).equals(List.of("teste01.docx", "teste02.docx")));
        check("user02 vê teste01 (grupo) e teste02 (dono)",
                nomes(lst.get("user02@inf1416.puc-rio.br")).equals(List.of("teste01.docx", "teste02.docx")));
        check("total de consultas incrementado", db.findUsuarioByEmail("user01@inf1416.puc-rio.br").numConsultas == 1);

        // Decriptação
        PrivateKey pk1 = CadastroService.chavePrivadaDoUsuario(db, u1, "user01".toCharArray(), 10240);
        u1 = db.findUsuarioByUid(u1.uid);
        CofreService.Listagem l1 = lst.get("user01@inf1416.puc-rio.br");
        for (CofreService.Entrada e : l1.entradas) {
            CofreService.Resultado res = s.cofre.decriptarArquivo(l1, e, u1, pk1);
            byte[] cab = Arrays.copyOf(Files.readAllBytes(res.arquivoGravado), 2);
            check("user01 decripta " + e.nomeSecreto + " (" + e.acesso + ") e grava DOCX válido",
                    cab[0] == 'P' && cab[1] == 'K');
        }
        Database.Usuario uAdmin = db.findUsuarioByEmail("admin@inf1416.puc-rio.br");
        CofreService.Listagem la = lst.get("admin@inf1416.puc-rio.br");
        CofreService.Resultado ra = s.cofre.decriptarArquivo(la, la.entradas.get(0), uAdmin, adminPk);
        check("admin decripta teste00.docx", ra.tamanho == 12007);

        Database.Usuario uu2 = db.findUsuarioByEmail("user02@inf1416.puc-rio.br");
        PrivateKey pk2 = CadastroService.chavePrivadaDoUsuario(db, uu2, "user02".toCharArray(), 10240);
        CofreService.Listagem l2 = lst.get("user02@inf1416.puc-rio.br");
        boolean falhouGrupo = false;
        try { s.cofre.decriptarArquivo(l2, l2.entradas.get(0), uu2, pk2); }
        catch (CofreService.CofreException ex) { falhouGrupo = true; System.out.println("    (esperado) " + ex.getMessage().split("\n")[0]); }
        check("user02 (só grupo) não tem envelope para teste01 -> 7020", falhouGrupo);

        // Integridade: adultera a assinatura do index
        Path pasta2 = tmp.resolve("pasta2");
        Files.createDirectories(pasta2);
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(files)) {
            for (Path f : ds) Files.copy(f, pasta2.resolve(f.getFileName()));
        }
        byte[] asd = Files.readAllBytes(pasta2.resolve("index.asd"));
        asd[10] ^= 1;
        Files.write(pasta2.resolve("index.asd"), asd);
        String msg = null;
        try { s.cofre.listar(pasta2.toString(), u1, adminPk, adminCert); }
        catch (CofreService.CofreException ex) { msg = ex.getMessage(); }
        check("index.asd adulterado -> falha de verificação (7008)", msg != null && msg.contains("integridade"));

        // Arquivo adulterado
        byte[] asd11 = Files.readAllBytes(pasta.resolve("XXYYZZ11.asd"));
        asd11[5] ^= 1;
        Files.write(pasta.resolve("XXYYZZ11.asd"), asd11);
        msg = null;
        try { s.cofre.decriptarArquivo(l1, l1.entradas.get(0), u1, pk1); }
        catch (CofreService.CofreException ex) { msg = ex.getMessage(); }
        check("XXYYZZ11.asd adulterado -> falha de verificação (7021)", msg != null && msg.contains("integridade"));

        db.close();
        System.out.println();
        System.out.println("Banco de teste: " + dbFile);
        System.out.println("Resultado: " + ok + " OK, " + falhas + " falha(s).");
        System.exit(falhas == 0 ? 0 : 1);
    }

    static List<String> nomes(CofreService.Listagem l) {
        List<String> n = new ArrayList<>();
        for (CofreService.Entrada e : l.entradas) n.add(e.nomeSecreto);
        return n;
    }
}
