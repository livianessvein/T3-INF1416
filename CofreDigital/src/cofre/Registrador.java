package cofre;

/**
 * Grava os registros de auditoria na tabela Registros: data/hora, MID,
 * usuário (UID) e arquivo selecionado. Nunca grava o texto da mensagem.
 */
public class Registrador {

    private final Database db;

    public Registrador(Database db) {
        this.db = db;
    }

    /** Registro sem usuário associado (ex.: 1001, 2001). */
    public void log(int mid) {
        gravar(mid, null, null, null);
    }

    /** Registro associado a um usuário identificado. */
    public void log(int mid, Database.Usuario u) {
        gravar(mid, u == null ? null : u.uid, null, null);
    }

    /** Registro associado a um usuário e a um arquivo (nome secreto). */
    public void log(int mid, Database.Usuario u, String arquivo) {
        gravar(mid, u == null ? null : u.uid, null, arquivo);
    }

    /** Login name não identificado (2005): não há UID, guarda-se o login informado. */
    public void logLoginNaoIdentificado(String loginInformado) {
        gravar(Mensagens.LOGIN_NAO_IDENTIFICADO, null, loginInformado, null);
    }

    private void gravar(int mid, Integer uid, String login, String arquivo) {
        try {
            db.inserirRegistro(System.currentTimeMillis(), mid, uid, login, arquivo);
        } catch (Exception e) {
            System.err.println("[Registro] Falha ao gravar registro " + mid + ": " + e.getMessage());
        }
    }
}
