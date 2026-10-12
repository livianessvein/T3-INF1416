package cofre;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Estado em memória do processo do Cofre Digital.
 *
 * A frase secreta e a chave privada do administrador ficam em memória
 * durante toda a execução (para abrir os envelopes de index e share) e são
 * apagadas quando o sistema é encerrado.
 */
public class Sessao {

    public final Database db;
    public final Registrador reg;
    public final AuthService auth;
    public final CadastroService cadastro;
    public final CofreService cofre;

    private char[] fraseAdmin;
    private PrivateKey chaveAdmin;
    private X509Certificate certAdmin;

    /** Usuário autenticado na sessão corrente (null fora de sessão). */
    private Database.Usuario usuario;

    public Sessao(Database db) {
        this.db = db;
        this.reg = new Registrador(db);
        this.auth = new AuthService(db, reg);
        this.cadastro = new CadastroService(db, reg);
        this.cofre = new CofreService(db, reg);
    }

    public void definirAdministrador(char[] frase, PrivateKey chave, X509Certificate cert) {
        apagarFraseAdmin();
        this.fraseAdmin = Arrays.copyOf(frase, frase.length);
        this.chaveAdmin = chave;
        this.certAdmin = cert;
    }

    public PrivateKey chaveAdmin() { return chaveAdmin; }
    public X509Certificate certAdmin() { return certAdmin; }
    public boolean temFraseAdmin() { return fraseAdmin != null; }

    public Database.Usuario usuario() { return usuario; }

    public void iniciarSessao(Database.Usuario u) {
        this.usuario = u;
        reg.log(Mensagens.SESSAO_INICIADA, u);
    }

    public void encerrarSessao() {
        if (usuario != null) {
            reg.log(Mensagens.SESSAO_ENCERRADA, usuario);
            usuario = null;
        }
    }

    /** Recarrega os dados do usuário corrente do banco (contadores). */
    public void recarregarUsuario() {
        if (usuario == null) return;
        try {
            Database.Usuario u = db.findUsuarioByUid(usuario.uid);
            if (u != null) usuario = u;
        } catch (Exception ignored) {}
    }

    private void apagarFraseAdmin() {
        if (fraseAdmin != null) {
            Arrays.fill(fraseAdmin, '\0');
            fraseAdmin = null;
        }
    }

    /** Encerramento do sistema: apaga segredos da memória e fecha o banco. */
    public void encerrarSistema() {
        encerrarSessao();
        reg.log(Mensagens.SISTEMA_ENCERRADO);
        apagarFraseAdmin();
        chaveAdmin = null;
        certAdmin = null;
        db.close();
    }
}
