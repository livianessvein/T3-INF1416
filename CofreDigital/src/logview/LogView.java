package logview;

import cofre.CryptoUtil;

import java.io.BufferedReader;
import java.io.Console;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;

public final class LogView {
    private static final int TAMANHO_TESTE = 2048;
    private static final int GID_ADMINISTRADOR = 1;

    private LogView() {}

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Uso: java -jar LogView.jar <caminho_da_chave_privada> [arquivo_do_banco]");
            System.exit(2);
        }
        Path chave = Paths.get(args[0]);
        String arquivoDb = args.length > 1 ? args[1] : "cofre.db";

        if (!Files.isRegularFile(chave)) {
            System.err.println("Caminho da chave privada inválido: " + chave);
            System.exit(1);
        }
        if (!Files.isRegularFile(Paths.get(arquivoDb))) {
            System.err.println("Banco de dados do Cofre Digital não encontrado: " + arquivoDb);
            System.exit(1);
        }

        char[] frase = lerFraseSecreta();
        if (frase == null || frase.length == 0) {
            System.err.println("Frase secreta não informada. Programa encerrado.");
            System.exit(1);
        }

        try (Connection conn = DriverManager.getConnection("jdbc:sqlite:" + arquivoDb)) {
            String admin = autenticar(conn, Files.readAllBytes(chave), frase);
            if (admin == null) {
                System.err.println("Verificação negativa: a chave privada não pertence a um administrador "
                        + "do Cofre Digital (ou a frase secreta é inválida). Programa encerrado.");
                System.exit(1);
            }
            System.out.println();
            System.out.println("Administrador autenticado: " + admin);
            System.out.println();
            listar(conn);
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            System.exit(1);
        } finally {
            Arrays.fill(frase, '\0');
        }
    }

    private static char[] lerFraseSecreta() {
        Console console = System.console();
        if (console != null)
            return console.readPassword("Frase secreta da chave privada: ");
        System.err.println("[aviso] Console indisponível: a frase secreta será lida da entrada padrão.");
        System.err.print("Frase secreta da chave privada: ");
        try {
            String l = new BufferedReader(new InputStreamReader(System.in)).readLine();
            return l == null ? null : l.toCharArray();
        } catch (Exception e) {
            return null;
        }
    }

    private static String autenticar(Connection conn, byte[] chaveCifrada, char[] frase) throws Exception {
        PrivateKey pk;
        try {
            pk = CryptoUtil.decryptPrivateKey(chaveCifrada, frase);
        } catch (CryptoUtil.KeyValidationException e) {
            return null;
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT u.email, c.certificado FROM Usuarios u JOIN Chaveiro c ON c.KID = u.KID " +
                "WHERE u.GID = ? ORDER BY u.UID")) {
            ps.setInt(1, GID_ADMINISTRADOR);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    X509Certificate cert = CryptoUtil.fromPem(rs.getString(2));
                    if (CryptoUtil.validateKeyPair(pk, cert.getPublicKey(), TAMANHO_TESTE))
                        return rs.getString(1);
                }
            }
        }
        return null;
    }

    private static void listar(Connection conn) throws Exception {
        SimpleDateFormat data = new SimpleDateFormat("dd/MM/yyyy");
        SimpleDateFormat hora = new SimpleDateFormat("HH:mm:ss.SSS");
        String sql =
            "SELECT r.RID, r.data_hora, r.MID, m.texto, COALESCE(u.email, r.login_name) AS login, r.arquivo " +
            "FROM Registros r JOIN Mensagens m ON m.MID = r.MID " +
            "LEFT JOIN Usuarios u ON u.UID = r.UID " +
            "ORDER BY r.data_hora, r.RID";
        System.out.printf("%-10s  %-12s  %-6s  %s%n", "DATA", "HORA", "CÓDIGO", "MENSAGEM");
        System.out.println("-".repeat(100));
        int n = 0;
        try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                Date d = new Date(rs.getLong(2));
                String texto = rs.getString(4);
                String login = rs.getString(5);
                String arq = rs.getString(6);
                texto = texto.replace("<login_name>", login == null ? "-" : login)
                             .replace("<arq_name>", arq == null ? "-" : arq);
                System.out.printf("%-10s  %-12s  %-6d  %s%n", data.format(d), hora.format(d), rs.getInt(3), texto);
                n++;
            }
        }
        System.out.println("-".repeat(100));
        System.out.println(n + " registro(s).");
    }
}
