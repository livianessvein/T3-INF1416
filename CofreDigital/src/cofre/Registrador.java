/*
 * Livian Essvein - 2211667
 * Breno Lois Matos - 2210780
 */

package cofre;

public class Registrador {
    private final Database db;

    public Registrador(Database db) {
        this.db = db;
    }

    public void log(int mid) {
        gravar(mid, null, null, null);
    }

    public void log(int mid, Database.Usuario u) {
        gravar(mid, u == null ? null : u.uid, null, null);
    }

    public void log(int mid, Database.Usuario u, String arquivo) {
        gravar(mid, u == null ? null : u.uid, null, arquivo);
    }

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
