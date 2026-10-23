/*
 * Livian Essvein - 2211667
 * Breno Lois Matos - 2210780
 */

package cofre;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CofreService {
    private final Database db;
    private final Registrador reg;

    public CofreService(Database db, Registrador reg) {
        this.db = db;
        this.reg = reg;
    }

    public static class CofreException extends Exception {
        public CofreException(String msg) { super(msg); }
    }

    public enum TipoAcesso { DONO, GRUPO, COMPARTILHADO }

    public static class Entrada {
        public String nomeCodigo;
        public String nomeSecreto;
        public String dono;
        public String grupo;
        public TipoAcesso acesso;
        public Integer idCompartilhamento;
    }

    public static class Listagem {
        public List<Entrada> entradas = new ArrayList<>();
        public List<String> avisos = new ArrayList<>();
        public Path pasta;
    }

    record LinhaShare(String nomeCodigo, int id, String usuario) {}

    public Listagem listar(String caminhoPasta, Database.Usuario u,
                           PrivateKey adminPriv, X509Certificate adminCert) throws CofreException {
        Path pasta;
        try {
            if (caminhoPasta == null || caminhoPasta.trim().isEmpty() || caminhoPasta.length() > 255)
                throw new Exception();
            pasta = Paths.get(caminhoPasta.trim());
            if (!Files.isDirectory(pasta)) throw new Exception();
            for (String ext : new String[] {".enc", ".env", ".asd"})
                if (!Files.isRegularFile(pasta.resolve("index" + ext))) throw new Exception();
        } catch (Exception e) {
            reg.log(Mensagens.CON_PASTA_INVALIDA, u);
            throw new CofreException("Caminho de pasta inválido: a pasta não existe ou não contém "
                    + "index.enc, index.env e index.asd.");
        }

        Listagem out = new Listagem();
        out.pasta = pasta;

        byte[] indexPlain;
        try {
            indexPlain = decriptar(pasta, "index", "index.env", adminPriv); // descriptografa
        } catch (Exception e) {
            reg.log(Mensagens.INDEX_FALHA_DECRIPTACAO, u);
            throw new CofreException("Falha na decriptação do arquivo de índice (sigilo): " + e.getMessage());
        }
        reg.log(Mensagens.INDEX_DECRIPTADO, u);
        if (!verificar(pasta, "index", indexPlain, adminCert)) {
            reg.log(Mensagens.INDEX_FALHA_VERIFICACAO, u);
            throw new CofreException("Falha na verificação de integridade e autenticidade do arquivo de índice.");
        }
        reg.log(Mensagens.INDEX_VERIFICADO, u);

        List<LinhaShare> shares = new ArrayList<>();
        boolean shareOk = false;
        if (Files.isRegularFile(pasta.resolve("share.enc"))) {
            byte[] sharePlain = null;
            try {
                sharePlain = decriptar(pasta, "share", "share.env", adminPriv);
                reg.log(Mensagens.SHARE_DECRIPTADO, u);
            } catch (Exception e) {
                reg.log(Mensagens.SHARE_FALHA_DECRIPTACAO, u);
                out.avisos.add("Falha na decriptação do arquivo de share: arquivos compartilhados não serão listados.");
            }
            if (sharePlain != null) {
                if (verificar(pasta, "share", sharePlain, adminCert)) {
                    reg.log(Mensagens.SHARE_VERIFICADO, u);
                    shares = parseShare(new String(sharePlain, StandardCharsets.US_ASCII));
                    shareOk = true;
                } else {
                    reg.log(Mensagens.SHARE_FALHA_VERIFICACAO, u);
                    out.avisos.add("Falha na verificação de integridade e autenticidade do arquivo de share: "
                            + "arquivos compartilhados não serão listados.");
                }
            }
        } else {
            out.avisos.add("A pasta não possui arquivo de share.");
        }

        String login = u.email;
        for (String linha : new String(indexPlain, StandardCharsets.US_ASCII).split("\n")) {
            String[] f = linha.trim().split("\\s+");
            if (f.length != 4) continue;
            Entrada e = new Entrada();
            e.nomeCodigo = f[0];
            e.nomeSecreto = f[1];
            e.dono = f[2];
            e.grupo = f[3];
            LinhaShare s = shareDoUsuario(shares, e.nomeCodigo, login);
            if (e.dono.equalsIgnoreCase(login)) {
                e.acesso = TipoAcesso.DONO;
            } else if (s != null) {
                e.acesso = TipoAcesso.COMPARTILHADO;
            } else if (e.grupo.equalsIgnoreCase(u.grupoNome)) {
                e.acesso = TipoAcesso.GRUPO;
            } else {
                continue;
            }
            if (s != null) e.idCompartilhamento = s.id();
            out.entradas.add(e);
        }

        try { db.incrementarConsultas(u.uid); u.numConsultas++; } catch (Exception ignored) {}

        reg.log(Mensagens.INDEX_LISTA_APRESENTADA, u);
        if (shareOk) reg.log(Mensagens.SHARE_LISTA_APRESENTADA, u);
        return out;
    }

    private static LinhaShare shareDoUsuario(List<LinhaShare> shares, String codigo, String login) {
        for (LinhaShare s : shares)
            if (s.nomeCodigo().equals(codigo) && s.usuario().equalsIgnoreCase(login))
                return s;
        return null;
    }

    static List<LinhaShare> parseShare(String texto) {
        List<LinhaShare> out = new ArrayList<>();
        for (String linha : texto.split("\n")) {
            String[] f = linha.trim().split("\\s+");
            if (f.length != 3) continue;
            try {
                int id = Integer.parseInt(f[1]);
                if (id > 0) out.add(new LinhaShare(f[0], id, f[2]));
            } catch (NumberFormatException ignored) {}
        }
        return out;
    }

    public static class Resultado {
        public Path arquivoGravado;
        public int tamanho;
    }

    public Resultado decriptarArquivo(Listagem listagem, Entrada e, Database.Usuario u,
                                      PrivateKey userPriv) throws CofreException {
        reg.log(Mensagens.ARQ_SELECIONADO, u, e.nomeSecreto);

        boolean dono = e.dono.equalsIgnoreCase(u.email);
        boolean compartilhado = e.idCompartilhamento != null;
        if (!listagem.entradas.contains(e) || !(dono || compartilhado)) {
            reg.log(Mensagens.ARQ_ACESSO_NEGADO, u, e.nomeSecreto);
            String msg = "Você não tem permissão de acesso ao arquivo " + e.nomeSecreto + ".";
            if (e.acesso == TipoAcesso.GRUPO)
                msg += "\nO arquivo pertence ao seu grupo (" + e.grupo + ") e por isso aparece na listagem,"
                        + "\nmas apenas o dono (" + e.dono + ") ou usuários com quem ele"
                        + "\ncompartilhou o arquivo podem acessar o seu conteúdo.";
            throw new CofreException(msg);
        }
        reg.log(Mensagens.ARQ_ACESSO_PERMITIDO, u, e.nomeSecreto);

        Path pasta = listagem.pasta;

        List<String> envelopes = new ArrayList<>();
        if (dono) envelopes.add(e.nomeCodigo + ".env");
        if (compartilhado) envelopes.add(e.nomeCodigo + "." + e.idCompartilhamento + ".shr");

        byte[] plain = null;
        String erro = null;
        for (String env : envelopes) {
            try {
                plain = decriptar(pasta, e.nomeCodigo, env, userPriv);
                break;
            } catch (Exception ex) {
                erro = ex.getMessage();
            }
        }
        if (plain == null) {
            reg.log(Mensagens.ARQ_FALHA_DECRIPTACAO, u, e.nomeSecreto);
            String msg = "Falha na decriptação do arquivo " + e.nomeSecreto + " (sigilo).";
            if (erro != null)
                msg += "\nDetalhe: " + erro;
            throw new CofreException(msg);
        }
        reg.log(Mensagens.ARQ_DECRIPTADO, u, e.nomeSecreto);

        X509Certificate certDono = null;
        try {
            certDono = CadastroService.certificadoDoUsuario(db, db.findUsuarioByEmail(e.dono));
        } catch (Exception ignored) {}
        if (certDono == null || !verificar(pasta, e.nomeCodigo, plain, certDono)) {
            Arrays.fill(plain, (byte) 0);
            reg.log(Mensagens.ARQ_FALHA_VERIFICACAO, u, e.nomeSecreto);
            throw new CofreException("Falha na verificação de integridade e autenticidade do arquivo "
                    + e.nomeSecreto + (certDono == null
                        ? ": o dono (" + e.dono + ") não possui certificado cadastrado no sistema."
                        : ": a assinatura digital não confere."));
        }
        reg.log(Mensagens.ARQ_VERIFICADO, u, e.nomeSecreto);

        try {
            Path nome = Paths.get(e.nomeSecreto).getFileName();
            if (nome == null || !nome.toString().equals(e.nomeSecreto))
                throw new Exception("nome secreto inválido");
            Path destino = pasta.resolve(nome);
            Files.write(destino, plain);
            Resultado r = new Resultado();
            r.arquivoGravado = destino.toAbsolutePath();
            r.tamanho = plain.length;
            return r;
        } catch (Exception ex) {
            throw new CofreException("O arquivo foi decriptado e verificado, mas não pôde ser gravado: "
                    + ex.getMessage());
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    private static byte[] decriptar(Path pasta, String nomeCodigo, String arquivoEnvelope,
                                    PrivateKey priv) throws Exception {
        byte[] envelope = Files.readAllBytes(pasta.resolve(arquivoEnvelope));
        byte[] semente = CryptoUtil.openEnvelope(envelope, priv);
        try {
            SecretKey k = CryptoUtil.aesKeyFromSeed(semente);
            return CryptoUtil.aesDecrypt(Files.readAllBytes(pasta.resolve(nomeCodigo + ".enc")), k);
        } finally {
            Arrays.fill(semente, (byte) 0);
        }
    }

    private static boolean verificar(Path pasta, String nomeCodigo, byte[] plain, X509Certificate cert) {
        try {
            byte[] asd = Files.readAllBytes(pasta.resolve(nomeCodigo + ".asd"));
            return CryptoUtil.verifySignature(plain, asd, cert.getPublicKey());
        } catch (Exception e) {
            return false;
        }
    }
}
