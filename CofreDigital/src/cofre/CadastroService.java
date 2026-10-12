package cofre;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;

/**
 * Cadastro de usuários (inclusive o administrador na partida do sistema).
 */
public class CadastroService {

    /** Tamanho do array aleatório assinado para validar a chave privada. */
    public static final int TAMANHO_TESTE_CHAVE = 10240;

    private final Database db;
    private final Registrador reg;

    public CadastroService(Database db, Registrador reg) {
        this.db = db;
        this.reg = reg;
    }

    /** Falha de cadastro, com o MID a ser registrado (ou 0 se não houver). */
    public static class CadastroException extends Exception {
        public final int mid;
        public CadastroException(int mid, String msg) {
            super(msg);
            this.mid = mid;
        }
    }

    /** Dados validados, prontos para confirmação e gravação. */
    public static class Preparado {
        public X509Certificate certificado;
        public String certificadoPem;
        public byte[] chavePrivadaCifrada;
        public String nome;
        public String email;
    }

    /** Resultado de um cadastro efetivado. */
    public static class Efetivado {
        public int uid;
        public String email;
        public String segredoBase32;
        public String otpauthUri;
    }

    // ------------------------------------------------------------------

    /**
     * Crítica da senha pessoal: 8, 9 ou 10 dígitos de 0 a 9, sem dígitos
     * repetidos em sequência, e igual à confirmação.
     *
     * @return mensagem de erro, ou {@code null} se válida
     */
    public static String validarSenha(char[] senha, char[] confirmacao) {
        if (senha == null || senha.length == 0)
            return "Informe a senha pessoal.";
        if (senha.length < 8 || senha.length > 10)
            return "A senha pessoal deve ter 8, 9 ou 10 números.";
        for (char c : senha)
            if (c < '0' || c > '9')
                return "A senha pessoal deve conter apenas dígitos de 0 a 9.";
        if (AuthService.temRepeticao(senha))
            return "A senha pessoal não pode conter sequências de números repetidos (ex.: 11, 222).";
        if (confirmacao == null || !Arrays.equals(senha, confirmacao))
            return "A senha pessoal e a confirmação não conferem.";
        return null;
    }

    /**
     * Carrega o certificado, decripta a chave privada com a frase secreta e
     * valida o par assinando 10240 bytes aleatórios.
     */
    public Preparado preparar(String caminhoCert, String caminhoChave, char[] frase,
                              Database.Usuario operador) throws CadastroException {
        Preparado p = new Preparado();

        // Certificado digital
        X509Certificate cert;
        try {
            Path pc = caminho(caminhoCert);
            cert = CryptoUtil.loadCertificate(Files.readAllBytes(pc));
        } catch (Exception e) {
            reg.log(Mensagens.CAD_CERT_INVALIDO, operador);
            throw new CadastroException(Mensagens.CAD_CERT_INVALIDO,
                    "Caminho do certificado digital inválido ou arquivo não é um certificado X.509.");
        }
        String email = CryptoUtil.subjectEmail(cert);
        String nome = CryptoUtil.subjectCN(cert);
        if (email == null || !AuthService.emailValido(email) || nome == null) {
            reg.log(Mensagens.CAD_CERT_INVALIDO, operador);
            throw new CadastroException(Mensagens.CAD_CERT_INVALIDO,
                    "O campo Sujeito do certificado não contém nome (CN) e e-mail válidos.");
        }

        // Chave privada
        byte[] chaveCifrada;
        try {
            Path pk = caminho(caminhoChave);
            chaveCifrada = Files.readAllBytes(pk);
        } catch (Exception e) {
            reg.log(Mensagens.CAD_CHAVE_CAMINHO, operador);
            throw new CadastroException(Mensagens.CAD_CHAVE_CAMINHO,
                    "Caminho do arquivo da chave privada inválido.");
        }
        if (frase == null || frase.length == 0) {
            reg.log(Mensagens.CAD_CHAVE_FRASE, operador);
            throw new CadastroException(Mensagens.CAD_CHAVE_FRASE, "Informe a frase secreta da chave privada.");
        }
        try {
            CryptoUtil.loadAndValidatePrivateKey(chaveCifrada, frase, cert, TAMANHO_TESTE_CHAVE);
        } catch (CryptoUtil.KeyValidationException e) {
            int mid = e.motivo == CryptoUtil.KeyValidationException.Motivo.ASSINATURA_INVALIDA
                    ? Mensagens.CAD_CHAVE_ASSINATURA : Mensagens.CAD_CHAVE_FRASE;
            reg.log(mid, operador);
            throw new CadastroException(mid, mid == Mensagens.CAD_CHAVE_ASSINATURA
                    ? "Assinatura digital inválida: a chave privada não corresponde ao certificado."
                    : "Frase secreta inválida para a chave privada.");
        }

        try {
            p.certificadoPem = CryptoUtil.toPem(cert);
        } catch (Exception e) {
            reg.log(Mensagens.CAD_CERT_INVALIDO, operador);
            throw new CadastroException(Mensagens.CAD_CERT_INVALIDO, "Falha ao converter o certificado para PEM.");
        }
        p.certificado = cert;
        p.chavePrivadaCifrada = chaveCifrada;
        p.nome = nome;
        p.email = email;
        return p;
    }

    /** Campos do certificado para a tela de confirmação. */
    public static String[][] camposConfirmacao(X509Certificate c) {
        SimpleDateFormat f = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
        return new String[][] {
            {"Versão", "v" + c.getVersion()},
            {"Série", c.getSerialNumber().toString() + " (0x" + c.getSerialNumber().toString(16).toUpperCase() + ")"},
            {"Validade", f.format(c.getNotBefore()) + "  até  " + f.format(c.getNotAfter())},
            {"Tipo de Assinatura", c.getSigAlgName()},
            {"Emissor", CryptoUtil.issuerCN(c) + "  [" + CryptoUtil.readableDN(c.getIssuerX500Principal()) + "]"},
            {"Sujeito (Friendly Name)", CryptoUtil.subjectCN(c)},
            {"E-mail", CryptoUtil.subjectEmail(c)},
        };
    }

    /**
     * Grava o usuário: hash bcrypt da senha, segredo TOTP (20 bytes, BASE32,
     * cifrado com AES-256 derivada da senha) e o par certificado/chave no Chaveiro.
     */
    public Efetivado efetivar(Preparado p, int gid, char[] senha) throws CadastroException {
        try {
            if (db.emailExiste(p.email))
                throw new CadastroException(0, "Já existe um usuário cadastrado com o login name " + p.email + ".");

            String hash = CryptoUtil.bcryptHash(senha);

            byte[] segredo = CryptoUtil.randomBytes(20);
            String base32 = new Base32(Base32.Alphabet.BASE32, false, false).toString(segredo);
            Arrays.fill(segredo, (byte) 0);

            SecretKey k = CryptoUtil.aesKeyFromSecret(senha);
            byte[] tokenCifrado = CryptoUtil.aesEncrypt(base32.getBytes(StandardCharsets.US_ASCII), k);

            int uid = db.inserirUsuario(p.nome, p.email, gid, hash, tokenCifrado,
                    p.certificadoPem, p.chavePrivadaCifrada);

            Efetivado e = new Efetivado();
            e.uid = uid;
            e.email = p.email;
            e.segredoBase32 = base32;
            e.otpauthUri = "otpauth://totp/Cofre%20Digital:" + p.email + "?secret=" + base32
                    + "&issuer=Cofre%20Digital";
            return e;
        } catch (CadastroException e) {
            throw e;
        } catch (Exception e) {
            throw new CadastroException(0, "Falha ao gravar o usuário: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------

    private static Path caminho(String s) throws Exception {
        if (s == null || s.trim().isEmpty() || s.length() > 255)
            throw new Exception("caminho inválido");
        Path p = Paths.get(s.trim());
        if (!Files.isRegularFile(p) || !Files.isReadable(p))
            throw new Exception("arquivo inexistente");
        return p;
    }

    /** Restaura e valida a chave privada armazenada no Chaveiro para um usuário. */
    public static PrivateKey chavePrivadaDoUsuario(Database db, Database.Usuario u, char[] frase,
                                                   int tamanhoTeste)
            throws Exception {
        if (u.kid == null) throw new Exception("Usuário sem par de chaves no Chaveiro.");
        Database.ParChaves par = db.findChaveiro(u.kid);
        if (par == null) throw new Exception("Par de chaves não encontrado no Chaveiro.");
        X509Certificate cert = CryptoUtil.fromPem(par.certificadoPem);
        return CryptoUtil.loadAndValidatePrivateKey(par.chavePrivadaCifrada, frase, cert, tamanhoTeste);
    }

    public static X509Certificate certificadoDoUsuario(Database db, Database.Usuario u) throws Exception {
        if (u == null || u.kid == null) return null;
        Database.ParChaves par = db.findChaveiro(u.kid);
        return par == null ? null : CryptoUtil.fromPem(par.certificadoPem);
    }
}
