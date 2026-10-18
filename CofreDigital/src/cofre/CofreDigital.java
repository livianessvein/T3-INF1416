package cofre;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CofreDigital extends JFrame {
    private final Sessao sessao;

    public CofreDigital(Sessao sessao) {
        super("Cofre Digital");
        this.sessao = sessao;
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                encerrarSistema();
            }
        });
        setSize(760, 620);
        setMinimumSize(new Dimension(640, 520));
        setLocationRelativeTo(null);
    }

    public Sessao sessao() { return sessao; }

    void trocar(JComponent tela) {
        setContentPane(tela);
        revalidate();
        repaint();
    }

    void partidaCadastroAdministrador() {
        sessao.reg.log(Mensagens.PARTIDA_CADASTRO_ADMIN);
        trocar(new TelaCadastro(this, null).painel());
        setVisible(true);
    }

    void administradorCadastradoNaPartida(char[] frase, PrivateKey chave, X509Certificate cert) {
        sessao.definirAdministrador(frase, chave, cert);
        Arrays.fill(frase, '\0');
        mostrarEtapa1();
    }

    boolean partidaOperacaoNormal() {
        sessao.reg.log(Mensagens.PARTIDA_OPERACAO_NORMAL);
        try {
            Database.Usuario admin = sessao.db.findAdministradorSistema();
            if (admin == null) throw new Exception("Administrador não encontrado no banco.");

            JPasswordField campo = new JPasswordField(28);
            Ui.limitar(campo, 255);
            JPanel p = new JPanel(new BorderLayout(0, 8));
            p.add(new JLabel("<html>Partida do sistema.<br>Informe a frase secreta da chave privada do "
                    + "administrador<br><b>" + admin.email + "</b>:</html>"), BorderLayout.NORTH);
            p.add(campo, BorderLayout.CENTER);
            JOptionPane pane = new JOptionPane(p, JOptionPane.QUESTION_MESSAGE, JOptionPane.OK_CANCEL_OPTION) {
                @Override public void selectInitialValue() { campo.requestFocusInWindow(); }
            };
            JDialog d = pane.createDialog(null, "Cofre Digital - Partida do Sistema");
            d.setVisible(true);
            Object op = pane.getValue();
            if (!(op instanceof Integer) || (Integer) op != JOptionPane.OK_OPTION) {
                Ui.aviso(null, "Partida cancelada. O sistema será encerrado.");
                return false;
            }
            char[] frase = campo.getPassword();
            try {
                PrivateKey pk = CadastroService.chavePrivadaDoUsuario(sessao.db, admin, frase,
                        CadastroService.TAMANHO_TESTE_CHAVE);
                X509Certificate cert = CadastroService.certificadoDoUsuario(sessao.db, admin);
                sessao.definirAdministrador(frase, pk, cert);
            } catch (CryptoUtil.KeyValidationException ex) {
                Ui.erro(null, "Validação da chave privada do administrador negativa:\n" + ex.getMessage()
                        + "\n\nO sistema será encerrado.");
                return false;
            } finally {
                Arrays.fill(frase, '\0');
            }
            return true;
        } catch (Exception ex) {
            Ui.erro(null, "Falha na partida do sistema: " + ex.getMessage() + "\nO sistema será encerrado.");
            return false;
        }
    }

    void mostrarEtapa1() {
        sessao.reg.log(Mensagens.AUT1_INICIADA);
        trocar(TelaAutenticacao.etapa1(this));
        setVisible(true);
    }

    void mostrarEtapa2(Database.Usuario u) {
        sessao.reg.log(Mensagens.AUT1_ENCERRADA);
        sessao.reg.log(Mensagens.AUT2_INICIADA, u);
        trocar(TelaAutenticacao.etapa2(this, u));
    }

    void mostrarEtapa3(Database.Usuario u, char[] senha) {
        sessao.reg.log(Mensagens.AUT2_ENCERRADA, u);
        sessao.reg.log(Mensagens.AUT3_INICIADA, u);
        trocar(TelaAutenticacao.etapa3(this, u, senha));
    }

    void autenticado(Database.Usuario u) {
        sessao.reg.log(Mensagens.AUT3_ENCERRADA, u);
        sessao.iniciarSessao(u);
        mostrarTelaPrincipal();
    }

    void mostrarTelaPrincipal() {
        sessao.recarregarUsuario();
        Database.Usuario u = sessao.usuario();
        sessao.reg.log(Mensagens.TELA_PRINCIPAL, u);

        JPanel menu = new JPanel();
        menu.setLayout(new BoxLayout(menu, BoxLayout.Y_AXIS));
        JLabel t = new JLabel("Menu Principal:");
        t.setFont(Ui.FONTE_NEGRITO);
        t.setAlignmentX(LEFT_ALIGNMENT);
        menu.add(t);
        menu.add(Box.createVerticalStrut(12));

        if (u.isAdmin()) {
            JButton b1 = itemMenu("1 – Cadastrar um novo usuário");
            b1.addActionListener(e -> {
                sessao.reg.log(Mensagens.MENU_OPCAO1, u);
                mostrarCadastro();
            });
            menu.add(b1);
            menu.add(Box.createVerticalStrut(8));
        }
        JButton b2 = itemMenu("2 – Consultar pasta de arquivos secretos do usuário");
        b2.addActionListener(e -> {
            sessao.reg.log(Mensagens.MENU_OPCAO2, u);
            mostrarConsulta();
        });
        menu.add(b2);
        menu.add(Box.createVerticalStrut(8));
        JButton b3 = itemMenu("3 – Sair do Sistema");
        b3.addActionListener(e -> {
            sessao.reg.log(Mensagens.MENU_OPCAO3, u);
            mostrarSaida();
        });
        menu.add(b3);

        trocar(Ui.tela(Ui.cabecalho(u),
                Ui.corpo1("Total de acessos do usuário: ", String.valueOf(u.numAcessos)),
                menu));
    }

    private JButton itemMenu(String texto) {
        JButton b = Ui.botao(texto);
        b.setHorizontalAlignment(SwingConstants.LEFT);
        b.setAlignmentX(LEFT_ALIGNMENT);
        b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        b.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Ui.BORDA), new EmptyBorder(8, 12, 8, 12)));
        return b;
    }

    void mostrarCadastro() {
        trocar(new TelaCadastro(this, sessao.usuario()).painel());
    }

    void mostrarConsulta() {
        trocar(new TelaConsulta(this, sessao.usuario()).painel());
    }

    void mostrarSaida() {
        sessao.recarregarUsuario();
        Database.Usuario u = sessao.usuario();
        sessao.reg.log(Mensagens.TELA_SAIDA, u);

        JPanel c2 = new JPanel();
        c2.setLayout(new BoxLayout(c2, BoxLayout.Y_AXIS));
        JLabel t = new JLabel("Saída do sistema:");
        t.setFont(Ui.FONTE_NEGRITO);
        t.setAlignmentX(LEFT_ALIGNMENT);
        JLabel msg = new JLabel("Pressione o botão Encerrar Sessão ou o botão Encerrar Sistema para confirmar.");
        msg.setFont(Ui.FONTE);
        msg.setAlignmentX(LEFT_ALIGNMENT);
        c2.add(t);
        c2.add(Box.createVerticalStrut(10));
        c2.add(msg);
        c2.add(Box.createVerticalStrut(18));

        JPanel linha1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        linha1.setOpaque(false);
        linha1.setAlignmentX(LEFT_ALIGNMENT);
        JButton sessaoBtn = Ui.botao("Encerrar Sessão");
        JButton sistemaBtn = Ui.botao("Encerrar Sistema");
        linha1.add(sessaoBtn);
        linha1.add(Box.createHorizontalStrut(8));
        linha1.add(sistemaBtn);
        c2.add(linha1);
        c2.add(Box.createVerticalStrut(8));
        JPanel linha2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        linha2.setOpaque(false);
        linha2.setAlignmentX(LEFT_ALIGNMENT);
        JButton voltar = Ui.botao("Voltar de Sair para o Menu Principal");
        linha2.add(voltar);
        c2.add(linha2);

        sessaoBtn.addActionListener(e -> {
            sessao.reg.log(Mensagens.SAI_ENCERRAR_SESSAO, u);
            sessao.encerrarSessao();
            mostrarEtapa1();
        });
        sistemaBtn.addActionListener(e -> {
            sessao.reg.log(Mensagens.SAI_ENCERRAR_SISTEMA, u);
            encerrarSistema();
        });
        voltar.addActionListener(e -> {
            sessao.reg.log(Mensagens.SAI_BOTAO_VOLTAR, u);
            mostrarTelaPrincipal();
        });

        JPanel topo = new JPanel(new BorderLayout());
        topo.setOpaque(false);
        c2.setOpaque(false);
        topo.add(c2, BorderLayout.NORTH);
        trocar(Ui.tela(Ui.cabecalho(u),
                Ui.corpo1("Total de acessos do usuário: ", String.valueOf(u.numAcessos)),
                topo));
    }

    void encerrarSistema() {
        sessao.encerrarSistema();
        dispose();
        System.exit(0);
    }

    public static void main(String[] args) {
        String arquivoDb = args.length > 0 ? args[0] : Database.DEFAULT_FILE;
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {}
        UIManager.put("OptionPane.messageFont", Ui.FONTE);
        UIManager.put("OptionPane.buttonFont", Ui.FONTE);

        Database db;
        try {
            db = new Database(arquivoDb);
        } catch (Exception e) {
            JOptionPane.showMessageDialog(null, "Não foi possível abrir o banco de dados: " + e.getMessage(),
                    "Cofre Digital", JOptionPane.ERROR_MESSAGE);
            System.exit(1);
            return;
        }
        Sessao sessao = new Sessao(db);
        sessao.reg.log(Mensagens.SISTEMA_INICIADO);

        SwingUtilities.invokeLater(() -> {
            CofreDigital app = new CofreDigital(sessao);
            try {
                if (db.countUsuarios() == 0) {
                    app.partidaCadastroAdministrador();
                } else if (app.partidaOperacaoNormal()) {
                    app.mostrarEtapa1();
                } else {
                    app.encerrarSistema();
                }
            } catch (Exception e) {
                Ui.erro(null, "Erro na partida do sistema: " + e.getMessage());
                app.encerrarSistema();
            }
        });
    }
}
