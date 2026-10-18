package cofre;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.OptionalInt;
import java.util.stream.IntStream;

public class AuthService {
    public static final int MAX_ERROS = 3;
    public static final long TEMPO_BLOQUEIO_MS = 2 * 60 * 1000L;

    private final Database db;
    private final Registrador reg;

    public AuthService(Database db, Registrador reg) {
        this.db = db;
        this.reg = reg;
    }

    public enum ResultadoEtapa1 { INVALIDO, NAO_IDENTIFICADO, BLOQUEADO, LIBERADO }

    public static class Etapa1 {
        public ResultadoEtapa1 resultado;
        public Database.Usuario usuario;
    }

    public static boolean emailValido(String s) {
        return s != null && s.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    }

    public Etapa1 verificarLogin(String login) throws SQLException {
        Etapa1 r = new Etapa1();
        String l = login == null ? "" : login.trim();
        Database.Usuario u = emailValido(l) ? db.findUsuarioByEmail(l) : null;
        if (u == null) {
            reg.logLoginNaoIdentificado(l);
            r.resultado = emailValido(l) ? ResultadoEtapa1.NAO_IDENTIFICADO : ResultadoEtapa1.INVALIDO;
            return r;
        }
        r.usuario = u;
        if (u.bloqueado()) {
            reg.log(Mensagens.LOGIN_BLOQUEADO, u);
            r.resultado = ResultadoEtapa1.BLOQUEADO;
        } else {
            reg.log(Mensagens.LOGIN_LIBERADO, u);
            r.resultado = ResultadoEtapa1.LIBERADO;
        }
        return r;
    }

    public static char[] encontrarSenha(String hashArmazenado, List<int[]> pares) {
        int n = pares.size();
        if (n < 8 || n > 10) return null;
        int[][] p = pares.toArray(new int[0][]);
        OptionalInt achada = IntStream.range(0, 1 << n).parallel()
                .filter(mask -> {
                    char[] cand = candidato(p, mask);
                    try {
                        if (temRepeticao(cand)) return false;
                        return CryptoUtil.bcryptCheck(hashArmazenado, cand);
                    } finally {
                        Arrays.fill(cand, '\0');
                    }
                })
                .findAny();
        return achada.isPresent() ? candidato(p, achada.getAsInt()) : null;
    }

    private static char[] candidato(int[][] pares, int mask) {
        char[] c = new char[pares.length];
        for (int i = 0; i < pares.length; i++)
            c[i] = (char) ('0' + pares[i][(mask >> i) & 1]);
        return c;
    }

    static boolean temRepeticao(char[] s) {
        for (int i = 1; i < s.length; i++)
            if (s[i] == s[i - 1]) return true;
        return false;
    }

    public enum ResultadoEtapa2 { OK, ERRO, BLOQUEADO }

    public ResultadoEtapa2 registrarErroSenha(Database.Usuario u) throws SQLException {
        u.errosSenha++;
        if (u.errosSenha == 1) reg.log(Mensagens.SENHA_ERRO1, u);
        else if (u.errosSenha == 2) reg.log(Mensagens.SENHA_ERRO2, u);
        else reg.log(Mensagens.SENHA_ERRO3, u);

        if (u.errosSenha >= MAX_ERROS) {
            u.bloqueadoAte = System.currentTimeMillis() + TEMPO_BLOQUEIO_MS;
            db.bloquear(u.uid, u.bloqueadoAte);
            u.errosSenha = 0;
            reg.log(Mensagens.SENHA_BLOQUEIO, u);
            return ResultadoEtapa2.BLOQUEADO;
        }
        db.setErrosSenha(u.uid, u.errosSenha);
        return ResultadoEtapa2.ERRO;
    }

    public void registrarSenhaOk(Database.Usuario u) throws SQLException {
        u.errosSenha = 0;
        db.setErrosSenha(u.uid, 0);
        reg.log(Mensagens.SENHA_OK, u);
    }

    public static String decriptarSegredoTotp(byte[] tokenKeyCifrada, char[] senha) throws Exception {
        SecretKey k = CryptoUtil.aesKeyFromSecret(senha);
        byte[] plain = CryptoUtil.aesDecrypt(tokenKeyCifrada, k);
        try {
            return new String(plain, StandardCharsets.US_ASCII);
        } finally {
            Arrays.fill(plain, (byte) 0);
        }
    }

    public static boolean validarToken(byte[] tokenKeyCifrada, char[] senha, String codigo) {
        try {
            TOTP totp = new TOTP(decriptarSegredoTotp(tokenKeyCifrada, senha), 30);
            return totp.validateCode(codigo);
        } catch (Exception e) {
            return false;
        }
    }

    public ResultadoEtapa2 registrarErroToken(Database.Usuario u) throws SQLException {
        u.errosToken++;
        if (u.errosToken == 1) reg.log(Mensagens.TOKEN_ERRO1, u);
        else if (u.errosToken == 2) reg.log(Mensagens.TOKEN_ERRO2, u);
        else reg.log(Mensagens.TOKEN_ERRO3, u);

        if (u.errosToken >= MAX_ERROS) {
            u.bloqueadoAte = System.currentTimeMillis() + TEMPO_BLOQUEIO_MS;
            db.bloquear(u.uid, u.bloqueadoAte);
            u.errosToken = 0;
            reg.log(Mensagens.TOKEN_BLOQUEIO, u);
            return ResultadoEtapa2.BLOQUEADO;
        }
        db.setErrosToken(u.uid, u.errosToken);
        return ResultadoEtapa2.ERRO;
    }

    public void registrarTokenOk(Database.Usuario u) throws SQLException {
        reg.log(Mensagens.TOKEN_OK, u);
        db.incrementarAcessos(u.uid);
        u.numAcessos++;
        u.errosToken = 0;
        u.errosSenha = 0;
    }
}
