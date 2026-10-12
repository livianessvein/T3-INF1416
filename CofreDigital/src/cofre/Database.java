package cofre;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Acesso ao banco SQLite do Cofre Digital.
 *
 * Tabelas: Grupos, Usuarios, Chaveiro, Mensagens e Registros.
 */
public class Database implements AutoCloseable {

    public static final String DEFAULT_FILE = "cofre.db";

    public static final int GID_ADMINISTRADOR = 1;
    public static final int GID_USUARIO = 2;

    private final Connection conn;

    public Database(String file) throws SQLException {
        conn = DriverManager.getConnection("jdbc:sqlite:" + file);
        try (Statement st = conn.createStatement()) {
            st.execute("PRAGMA foreign_keys = ON");
        }
        createSchema();
        seed();
    }

    private void createSchema() throws SQLException {
        try (Statement st = conn.createStatement()) {
            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS Grupos (" +
                "  GID   INTEGER PRIMARY KEY," +
                "  nome  TEXT NOT NULL UNIQUE)");

            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS Usuarios (" +
                "  UID            INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  nome           TEXT    NOT NULL," +
                "  email          TEXT    NOT NULL UNIQUE," +      // login name
                "  GID            INTEGER NOT NULL REFERENCES Grupos(GID)," +
                "  senha          CHAR(60) NOT NULL," +            // bcrypt $2y$08$...
                "  token_key      BLOB    NOT NULL," +             // BASE32(segredo TOTP) cifrado AES
                "  KID            INTEGER," +                      // par ativo no Chaveiro
                "  num_acessos    INTEGER NOT NULL DEFAULT 0," +
                "  num_consultas  INTEGER NOT NULL DEFAULT 0," +
                "  erros_senha    INTEGER NOT NULL DEFAULT 0," +
                "  erros_token    INTEGER NOT NULL DEFAULT 0," +
                "  bloqueado_ate  INTEGER NOT NULL DEFAULT 0)");   // epoch ms

            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS Chaveiro (" +
                "  KID            INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  UID            INTEGER NOT NULL REFERENCES Usuarios(UID)," +
                "  certificado    TEXT    NOT NULL," +             // PEM
                "  chave_privada  BLOB    NOT NULL)");             // binário criptografado

            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS Mensagens (" +
                "  MID    INTEGER PRIMARY KEY," +
                "  texto  TEXT NOT NULL)");

            st.executeUpdate(
                "CREATE TABLE IF NOT EXISTS Registros (" +
                "  RID        INTEGER PRIMARY KEY AUTOINCREMENT," +
                "  data_hora  INTEGER NOT NULL," +                 // epoch ms
                "  MID        INTEGER NOT NULL REFERENCES Mensagens(MID)," +
                "  UID        INTEGER REFERENCES Usuarios(UID)," + // usuário identificado
                "  login_name TEXT," +                             // só p/ login não identificado (2005)
                "  arquivo    TEXT)");                             // arquivo selecionado (7015-7021)
        }
    }

    private void seed() throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR IGNORE INTO Grupos (GID, nome) VALUES (?, ?)")) {
            ps.setInt(1, GID_ADMINISTRADOR); ps.setString(2, "administrador"); ps.executeUpdate();
            ps.setInt(1, GID_USUARIO);       ps.setString(2, "usuario");       ps.executeUpdate();
        }
        conn.setAutoCommit(false);
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT OR REPLACE INTO Mensagens (MID, texto) VALUES (?, ?)")) {
            for (Map.Entry<Integer, String> e : Mensagens.TODAS.entrySet()) {
                ps.setInt(1, e.getKey());
                ps.setString(2, e.getValue());
                ps.addBatch();
            }
            ps.executeBatch();
            conn.commit();
        } finally {
            conn.setAutoCommit(true);
        }
    }

    // ------------------------------------------------------------------
    // Usuários
    // ------------------------------------------------------------------

    public static class Usuario {
        public int uid;
        public String nome;
        public String email;
        public int gid;
        public String grupoNome;
        public String senhaHash;
        public byte[] tokenKeyCifrada;
        public Integer kid;
        public int numAcessos;
        public int numConsultas;
        public int errosSenha;
        public int errosToken;
        public long bloqueadoAte;

        public boolean isAdmin() { return gid == GID_ADMINISTRADOR; }

        /** Nome do grupo para exibição nas telas. */
        public String grupoExibicao() { return isAdmin() ? "Administrador" : "Usuário"; }

        public boolean bloqueado() { return bloqueadoAte > System.currentTimeMillis(); }
    }

    private static final String SELECT_USUARIO =
        "SELECT u.UID, u.nome, u.email, u.GID, g.nome AS gnome, u.senha, u.token_key, u.KID," +
        "       u.num_acessos, u.num_consultas, u.erros_senha, u.erros_token, u.bloqueado_ate " +
        "FROM Usuarios u JOIN Grupos g ON g.GID = u.GID ";

    private Usuario mapUsuario(ResultSet rs) throws SQLException {
        Usuario u = new Usuario();
        u.uid = rs.getInt("UID");
        u.nome = rs.getString("nome");
        u.email = rs.getString("email");
        u.gid = rs.getInt("GID");
        u.grupoNome = rs.getString("gnome");
        u.senhaHash = rs.getString("senha");
        u.tokenKeyCifrada = rs.getBytes("token_key");
        int kid = rs.getInt("KID");
        u.kid = rs.wasNull() ? null : kid;
        u.numAcessos = rs.getInt("num_acessos");
        u.numConsultas = rs.getInt("num_consultas");
        u.errosSenha = rs.getInt("erros_senha");
        u.errosToken = rs.getInt("erros_token");
        u.bloqueadoAte = rs.getLong("bloqueado_ate");
        return u;
    }

    public Usuario findUsuarioByEmail(String email) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(SELECT_USUARIO + "WHERE lower(u.email) = lower(?)")) {
            ps.setString(1, email);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapUsuario(rs) : null;
            }
        }
    }

    public Usuario findUsuarioByUid(int uid) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(SELECT_USUARIO + "WHERE u.UID = ?")) {
            ps.setInt(1, uid);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapUsuario(rs) : null;
            }
        }
    }

    /** Administrador do sistema: o primeiro administrador cadastrado (partida do sistema). */
    public Usuario findAdministradorSistema() throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                SELECT_USUARIO + "WHERE u.GID = ? ORDER BY u.UID LIMIT 1")) {
            ps.setInt(1, GID_ADMINISTRADOR);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? mapUsuario(rs) : null;
            }
        }
    }

    public List<Usuario> listAdministradores() throws SQLException {
        List<Usuario> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(SELECT_USUARIO + "WHERE u.GID = ? ORDER BY u.UID")) {
            ps.setInt(1, GID_ADMINISTRADOR);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(mapUsuario(rs));
            }
        }
        return out;
    }

    public int countUsuarios() throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM Usuarios")) {
            return rs.next() ? rs.getInt(1) : 0;
        }
    }

    public boolean emailExiste(String email) throws SQLException {
        return findUsuarioByEmail(email) != null;
    }

    /**
     * Cadastra o usuário e seu par chave privada/certificado no Chaveiro,
     * associando o KID gerado ao registro do usuário. Operação atômica.
     */
    public int inserirUsuario(String nome, String email, int gid, String senhaHash,
                              byte[] tokenKeyCifrada, String certificadoPem,
                              byte[] chavePrivadaCifrada) throws SQLException {
        boolean auto = conn.getAutoCommit();
        conn.setAutoCommit(false);
        try {
            int uid;
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO Usuarios (nome, email, GID, senha, token_key) VALUES (?, ?, ?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, nome);
                ps.setString(2, email);
                ps.setInt(3, gid);
                ps.setString(4, senhaHash);
                ps.setBytes(5, tokenKeyCifrada);
                ps.executeUpdate();
                try (ResultSet rs = ps.getGeneratedKeys()) { rs.next(); uid = rs.getInt(1); }
            }
            int kid;
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO Chaveiro (UID, certificado, chave_privada) VALUES (?, ?, ?)",
                    Statement.RETURN_GENERATED_KEYS)) {
                ps.setInt(1, uid);
                ps.setString(2, certificadoPem);
                ps.setBytes(3, chavePrivadaCifrada);
                ps.executeUpdate();
                try (ResultSet rs = ps.getGeneratedKeys()) { rs.next(); kid = rs.getInt(1); }
            }
            try (PreparedStatement ps = conn.prepareStatement("UPDATE Usuarios SET KID = ? WHERE UID = ?")) {
                ps.setInt(1, kid);
                ps.setInt(2, uid);
                ps.executeUpdate();
            }
            conn.commit();
            return uid;
        } catch (SQLException e) {
            conn.rollback();
            throw e;
        } finally {
            conn.setAutoCommit(auto);
        }
    }

    public void setErrosSenha(int uid, int erros) throws SQLException {
        exec("UPDATE Usuarios SET erros_senha = ? WHERE UID = ?", erros, uid);
    }

    public void setErrosToken(int uid, int erros) throws SQLException {
        exec("UPDATE Usuarios SET erros_token = ? WHERE UID = ?", erros, uid);
    }

    public void bloquear(int uid, long ateEpochMs) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE Usuarios SET bloqueado_ate = ?, erros_senha = 0, erros_token = 0 WHERE UID = ?")) {
            ps.setLong(1, ateEpochMs);
            ps.setInt(2, uid);
            ps.executeUpdate();
        }
    }

    public void incrementarAcessos(int uid) throws SQLException {
        exec("UPDATE Usuarios SET num_acessos = num_acessos + 1, erros_senha = 0, erros_token = 0 WHERE UID = ?", uid);
    }

    public void incrementarConsultas(int uid) throws SQLException {
        exec("UPDATE Usuarios SET num_consultas = num_consultas + 1 WHERE UID = ?", uid);
    }

    // ------------------------------------------------------------------
    // Chaveiro
    // ------------------------------------------------------------------

    public static class ParChaves {
        public int kid;
        public int uid;
        public String certificadoPem;
        public byte[] chavePrivadaCifrada;
    }

    public ParChaves findChaveiro(int kid) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT KID, UID, certificado, chave_privada FROM Chaveiro WHERE KID = ?")) {
            ps.setInt(1, kid);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                ParChaves p = new ParChaves();
                p.kid = rs.getInt(1);
                p.uid = rs.getInt(2);
                p.certificadoPem = rs.getString(3);
                p.chavePrivadaCifrada = rs.getBytes(4);
                return p;
            }
        }
    }

    // ------------------------------------------------------------------
    // Registros
    // ------------------------------------------------------------------

    public void inserirRegistro(long dataHora, int mid, Integer uid, String loginName, String arquivo)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO Registros (data_hora, MID, UID, login_name, arquivo) VALUES (?, ?, ?, ?, ?)")) {
            ps.setLong(1, dataHora);
            ps.setInt(2, mid);
            if (uid == null) ps.setNull(3, Types.INTEGER); else ps.setInt(3, uid);
            ps.setString(4, loginName);
            ps.setString(5, arquivo);
            ps.executeUpdate();
        }
    }

    // ------------------------------------------------------------------

    private void exec(String sql, Object... params) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            for (int i = 0; i < params.length; i++) ps.setObject(i + 1, params[i]);
            ps.executeUpdate();
        }
    }

    @Override
    public void close() {
        try { conn.close(); } catch (SQLException ignored) {}
    }
}
