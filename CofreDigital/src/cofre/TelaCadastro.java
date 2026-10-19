/*
 * Livian Essvein - 2211667
 * Breno Lois Matos - 2210780
 */

package cofre;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;

final class TelaCadastro {
    private final CofreDigital app;
    private final Sessao s;
    private final Database.Usuario operador;
    private final boolean partida;

    private final JTextField cert = new JTextField(34);
    private final JTextField chave = new JTextField(34);
    private final JPasswordField frase = new JPasswordField(34);
    private final JComboBox<String> grupo = new JComboBox<>(new String[] {"Administrador", "Usuário"});
    private final JPasswordField senha = new JPasswordField(12);
    private final JPasswordField confirmacao = new JPasswordField(12);
    private JLabel totalUsuarios;

    TelaCadastro(CofreDigital app, Database.Usuario operador) {
        this.app = app;
        this.s = app.sessao();
        this.operador = operador;
        this.partida = operador == null;
        Ui.limitar(cert, 255);
        Ui.limitar(chave, 255);
        Ui.limitar(frase, 255);
        Ui.limitar(senha, 10);
        Ui.limitar(confirmacao, 10);
        if (partida) {
            grupo.setSelectedIndex(0);
            grupo.setEnabled(false);
        } else {
            grupo.setSelectedIndex(1);
            s.reg.log(Mensagens.TELA_CADASTRO, operador);
        }
    }

    JPanel painel() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 0, 4, 8);

        JLabel t = new JLabel("Formulário de Cadastro:");
        t.setFont(Ui.FONTE_NEGRITO);
        g.gridwidth = 3;
        form.add(t, g);
        g.gridwidth = 1;

        int y = 1;
        y = linha(form, y, "Caminho do arquivo do certificado digital:", cert, seletor(cert));
        y = linha(form, y, "Caminho do arquivo da chave privada:", chave, seletor(chave));
        y = linha(form, y, "Frase secreta:", frase, null);
        y = linha(form, y, "Grupo:", grupo, null);
        y = linha(form, y, "Senha pessoal:", senha, null);
        y = linha(form, y, "Confirmação senha pessoal:", confirmacao, null);

        JLabel regra = new JLabel("Senha pessoal: 8, 9 ou 10 dígitos (0-9), sem números repetidos em sequência.");
        regra.setFont(Ui.FONTE.deriveFont(12f));
        regra.setForeground(Ui.SUAVE);
        g.gridx = 0; g.gridy = y++; g.gridwidth = 3;
        form.add(regra, g);

        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        botoes.setOpaque(false);
        JButton cadastrar = Ui.botao("Cadastrar");
        botoes.add(cadastrar);
        cadastrar.addActionListener(e -> cadastrar());
        if (!partida) {
            JButton voltar = Ui.botao("Voltar de Cadastrar para o Menu Principal");
            botoes.add(Box.createHorizontalStrut(8));
            botoes.add(voltar);
            voltar.addActionListener(e -> {
                s.reg.log(Mensagens.CAD_BOTAO_VOLTAR, operador);
                limparSegredos();
                app.mostrarTelaPrincipal();
            });
        }
        g.gridy = y; g.insets = new Insets(14, 0, 0, 0);
        form.add(botoes, g);

        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setOpaque(false);
        wrap.add(form, BorderLayout.NORTH);

        if (partida) {
            JPanel cab = new JPanel(new GridLayout(2, 1, 0, 4));
            cab.add(Ui.titulo("Partida do sistema"));
            JLabel l = new JLabel("Nenhum usuário cadastrado. Cadastre o administrador da pasta segura.");
            l.setFont(Ui.FONTE);
            cab.add(l);
            return Ui.tela(Ui.secao("Cabeçalho", cab), null, wrap);
        }
        JPanel linhaTotal = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JLabel k = new JLabel("Total de usuários do sistema: ");
        k.setFont(Ui.FONTE_NEGRITO);
        totalUsuarios = new JLabel(String.valueOf(contarUsuarios()));
        totalUsuarios.setFont(Ui.FONTE);
        linhaTotal.add(k);
        linhaTotal.add(totalUsuarios);
        return Ui.tela(Ui.cabecalho(operador), Ui.secao("Corpo 1", linhaTotal), wrap);
    }

    private int contarUsuarios() {
        try { return s.db.countUsuarios(); } catch (Exception e) { return 0; }
    }

    private int linha(JPanel p, int y, String rotulo, JComponent campo, JComponent extra) {
        GridBagConstraints g = new GridBagConstraints();
        g.gridy = y;
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 0, 4, 8);
        JLabel l = new JLabel(rotulo);
        l.setFont(Ui.FONTE);
        p.add(l, g);
        g.gridx = 1;
        campo.setFont(Ui.FONTE);
        if (!(campo instanceof JComboBox)) {
            g.fill = GridBagConstraints.HORIZONTAL;
            g.weightx = 1;
            campo.setMinimumSize(new Dimension(220, campo.getPreferredSize().height));
        }
        p.add(campo, g);
        if (extra != null) {
            g.gridx = 2;
            g.fill = GridBagConstraints.NONE;
            g.weightx = 0;
            p.add(extra, g);
        }
        return y + 1;
    }

    private JButton seletor(JTextField alvo) {
        JButton b = Ui.botao("...");
        b.setMargin(new Insets(2, 6, 2, 6));
        b.addActionListener(e -> {
            JFileChooser fc = new JFileChooser(alvo.getText().isEmpty() ? null : alvo.getText());
            if (fc.showOpenDialog(app) == JFileChooser.APPROVE_OPTION)
                alvo.setText(fc.getSelectedFile().getAbsolutePath());
        });
        return b;
    }

    private void cadastrar() {
        s.reg.log(Mensagens.CAD_BOTAO_CADASTRAR, operador);

        char[] sen = senha.getPassword();
        char[] conf = confirmacao.getPassword();
        char[] fr = frase.getPassword();
        try {
            String erroSenha = CadastroService.validarSenha(sen, conf);
            if (erroSenha != null) {
                s.reg.log(Mensagens.CAD_SENHA_INVALIDA, operador);
                Ui.erro(app, erroSenha);
                return;
            }

            CadastroService.Preparado p;
            try {
                p = s.cadastro.preparar(cert.getText(), chave.getText(), fr, operador);
            } catch (CadastroService.CadastroException ex) {
                Ui.erro(app, ex.getMessage());
                return;
            }

            if (!confirmar(p.certificado)) {
                s.reg.log(Mensagens.CAD_CONFIRMACAO_REJEITADA, operador);
                return;
            }
            s.reg.log(Mensagens.CAD_CONFIRMACAO_ACEITA, operador);

            int gid = grupo.getSelectedIndex() == 0 ? Database.GID_ADMINISTRADOR : Database.GID_USUARIO;
            CadastroService.Efetivado ef;
            try {
                ef = s.cadastro.efetivar(p, gid, sen);
            } catch (CadastroService.CadastroException ex) {
                Ui.erro(app, ex.getMessage());
                return;
            }

            mostrarSegredoTotp(ef);

            if (partida) {
                PrivateKey pk;
                try {
                    pk = CryptoUtil.loadAndValidatePrivateKey(p.chavePrivadaCifrada, fr, p.certificado,
                            CadastroService.TAMANHO_TESTE_CHAVE);
                } catch (Exception ex) {
                    Ui.erro(app, "Falha ao carregar a chave do administrador: " + ex.getMessage());
                    return;
                }
                char[] copia = Arrays.copyOf(fr, fr.length);
                limparFormulario();
                app.administradorCadastradoNaPartida(copia, pk, p.certificado);
                return;
            }

            limparFormulario();
            if (totalUsuarios != null) totalUsuarios.setText(String.valueOf(contarUsuarios()));
        } catch (Exception ex) {
            Ui.erro(app, "Erro no cadastro: " + ex.getMessage());
        } finally {
            Arrays.fill(sen, '\0');
            Arrays.fill(conf, '\0');
            Arrays.fill(fr, '\0');
        }
    }

    private boolean confirmar(X509Certificate c) {
        String[][] campos = CadastroService.camposConfirmacao(c);
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.NORTHWEST;
        g.insets = new Insets(3, 0, 3, 12);
        JLabel t = new JLabel("Confirme os dados do certificado digital:");
        t.setFont(Ui.FONTE_NEGRITO);
        g.gridwidth = 2;
        p.add(t, g);
        g.gridwidth = 1;
        for (int i = 0; i < campos.length; i++) {
            g.gridy = i + 1;
            g.gridx = 0;
            JLabel k = new JLabel(campos[i][0] + ":");
            k.setFont(Ui.FONTE_NEGRITO);
            p.add(k, g);
            g.gridx = 1;
            JLabel v = new JLabel("<html><div style='width:380px'>" + escapar(campos[i][1]) + "</div></html>");
            v.setFont(Ui.FONTE);
            p.add(v, g);
        }
        g.gridy = campos.length + 1; g.gridx = 0; g.gridwidth = 2;
        JLabel grp = new JLabel("Grupo: " + grupo.getSelectedItem());
        grp.setFont(Ui.FONTE);
        p.add(grp, g);
        Object[] op = {"Confirmar", "Rejeitar"};
        int r = JOptionPane.showOptionDialog(app, p, "Cofre Digital - Confirmação de Cadastro",
                JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE, null, op, op[0]);
        return r == 0;
    }

    private static String escapar(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private void mostrarSegredoTotp(CadastroService.Efetivado ef) {
        JPanel p = new JPanel(new BorderLayout(0, 10));
        p.setBorder(new EmptyBorder(4, 4, 4, 4));
        JLabel l = new JLabel("<html><b>Usuário " + escapar(ef.email) + " cadastrado com sucesso.</b><br><br>"
                + "Cadastre a chave abaixo no Google Authenticator<br>"
                + "(Adicionar código → Inserir chave de configuração, tipo: baseado em tempo):</html>");
        l.setFont(Ui.FONTE);
        p.add(l, BorderLayout.NORTH);

        JTextField segredo = new JTextField(agrupar(ef.segredoBase32));
        segredo.setEditable(false);
        segredo.setFont(Ui.FONTE_TECLA.deriveFont(18f));
        segredo.setHorizontalAlignment(JTextField.CENTER);

        JTextArea uri = new JTextArea(ef.otpauthUri, 2, 40);
        uri.setLineWrap(true);
        uri.setEditable(false);
        uri.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JPanel centro = new JPanel(new BorderLayout(0, 8));
        centro.add(segredo, BorderLayout.NORTH);
        JPanel uriBox = new JPanel(new BorderLayout(0, 4));
        JLabel ul = new JLabel("URI otpauth:");
        ul.setFont(Ui.FONTE.deriveFont(12f));
        uriBox.add(ul, BorderLayout.NORTH);
        uriBox.add(new JScrollPane(uri), BorderLayout.CENTER);
        centro.add(uriBox, BorderLayout.CENTER);
        p.add(centro, BorderLayout.CENTER);

        JButton copiar = Ui.botao("Copiar chave");
        copiar.addActionListener(e -> {
            try {
                Toolkit.getDefaultToolkit().getSystemClipboard()
                        .setContents(new StringSelection(ef.segredoBase32), null);
            } catch (Exception ignored) {}
        });
        JPanel sul = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        sul.add(copiar);
        p.add(sul, BorderLayout.SOUTH);

        JOptionPane.showMessageDialog(app, p, "Cofre Digital - Chave TOTP", JOptionPane.INFORMATION_MESSAGE);
    }

    private static String agrupar(String b32) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b32.length(); i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(b32.charAt(i));
        }
        return sb.toString();
    }

    private void limparSegredos() {
        frase.setText("");
        senha.setText("");
        confirmacao.setText("");
    }

    private void limparFormulario() {
        cert.setText("");
        chave.setText("");
        limparSegredos();
        if (!partida) grupo.setSelectedIndex(1);
    }
}
