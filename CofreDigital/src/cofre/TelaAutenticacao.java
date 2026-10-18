package cofre;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

final class TelaAutenticacao {
    private TelaAutenticacao() {}

    private static JPanel moldura(String subtitulo, JComponent conteudo) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBackground(Ui.FUNDO);

        JPanel cartao = new JPanel(new BorderLayout(0, 14));
        cartao.setBackground(Ui.PAINEL);
        cartao.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Ui.BORDA), new EmptyBorder(22, 26, 22, 26)));

        JPanel topo = new JPanel(new GridLayout(2, 1, 0, 2));
        topo.setOpaque(false);
        topo.add(Ui.titulo("Cofre Digital - Autenticação"));
        JLabel sub = new JLabel(subtitulo);
        sub.setFont(Ui.FONTE.deriveFont(12f));
        sub.setForeground(Ui.SUAVE);
        topo.add(sub);
        cartao.add(topo, BorderLayout.NORTH);
        conteudo.setOpaque(false);
        cartao.add(conteudo, BorderLayout.CENTER);
        p.add(cartao);
        return p;
    }

    static JPanel etapa1(CofreDigital app) {
        Sessao s = app.sessao();
        JTextField login = new JTextField(28);
        login.setFont(Ui.FONTE);
        Ui.limitar(login, 255);
        JButton ok = Ui.botao("OK");
        JButton limpar = Ui.botao("LIMPAR");

        JPanel c = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 0, 4, 8);
        g.anchor = GridBagConstraints.WEST;
        JLabel l = new JLabel("Login name:");
        l.setFont(Ui.FONTE_NEGRITO);
        c.add(l, g);
        g.gridx = 1;
        c.add(login, g);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botoes.setOpaque(false);
        botoes.add(ok);
        botoes.add(limpar);
        g.gridx = 0; g.gridy = 1; g.gridwidth = 2; g.anchor = GridBagConstraints.EAST;
        g.insets = new Insets(14, 0, 0, 0);
        c.add(botoes, g);

        Runnable enviar = () -> {
            try {
                AuthService.Etapa1 r = s.auth.verificarLogin(login.getText());
                switch (r.resultado) {
                    case INVALIDO:
                        Ui.erro(app, "Identificação inválida: informe um e-mail válido.");
                        break;
                    case NAO_IDENTIFICADO:
                        Ui.erro(app, "Login name não identificado.");
                        break;
                    case BLOQUEADO:
                        long seg = Math.max(1, (r.usuario.bloqueadoAte - System.currentTimeMillis() + 999) / 1000);
                        Ui.aviso(app, "O acesso do usuário " + r.usuario.email + " está bloqueado.\n"
                                + "Tente novamente após " + new SimpleDateFormat("HH:mm:ss")
                                .format(new Date(r.usuario.bloqueadoAte)) + " (" + seg + " s).");
                        break;
                    case LIBERADO:
                        app.mostrarEtapa2(r.usuario);
                        return;
                }
                login.selectAll();
                login.requestFocusInWindow();
            } catch (Exception ex) {
                Ui.erro(app, "Erro ao verificar o login name: " + ex.getMessage());
            }
        };
        ok.addActionListener(e -> enviar.run());
        login.addActionListener(e -> enviar.run());
        limpar.addActionListener(e -> { login.setText(""); login.requestFocusInWindow(); });

        JPanel tela = moldura("Etapa 1 de 3 – Identificação do usuário", c);
        SwingUtilities.invokeLater(login::requestFocusInWindow);
        return tela;
    }

    static JPanel etapa2(CofreDigital app, Database.Usuario u) {
        return new TecladoVirtual(app, u).tela;
    }

    private static final class TecladoVirtual {
        final CofreDigital app;
        final Database.Usuario u;
        final JPanel tela;
        final JButton[] teclas = new JButton[5];
        final int[][] distribuicao = new int[5][2];
        final List<int[]> pressionados = new ArrayList<>();
        final JLabel visor = new JLabel();
        final JLabel status = new JLabel(" ");
        final JButton ok = Ui.botao("OK");
        final JButton limpar = Ui.botao("LIMPAR");

        TecladoVirtual(CofreDigital app, Database.Usuario u) {
            this.app = app;
            this.u = u;

            JPanel c = new JPanel(new BorderLayout(0, 14));

            JPanel linhaVisor = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
            linhaVisor.setOpaque(false);
            JLabel l = new JLabel("Senha pessoal:  ");
            l.setFont(Ui.FONTE_NEGRITO);
            visor.setFont(Ui.FONTE_TECLA.deriveFont(18f));
            visor.setForeground(Ui.DESTAQUE);
            linhaVisor.add(l);
            linhaVisor.add(visor);
            c.add(linhaVisor, BorderLayout.NORTH);

            JPanel grade = new JPanel(new GridLayout(2, 4, 10, 10));
            grade.setOpaque(false);
            for (int i = 0; i < 5; i++) {
                final int idx = i;
                teclas[i] = new JButton();
                teclas[i].setFont(Ui.FONTE_TECLA);
                teclas[i].setFocusPainted(false);
                teclas[i].setPreferredSize(new Dimension(96, 58));
                teclas[i].addActionListener(e -> pressionar(idx));
            }
            grade.add(teclas[0]); grade.add(teclas[1]); grade.add(teclas[2]); grade.add(ok);
            grade.add(teclas[3]); grade.add(teclas[4]); grade.add(new JLabel()); grade.add(limpar);
            c.add(grade, BorderLayout.CENTER);

            status.setFont(Ui.FONTE.deriveFont(12f));
            status.setForeground(Ui.SUAVE);
            c.add(status, BorderLayout.SOUTH);

            ok.addActionListener(e -> verificar());
            limpar.addActionListener(e -> limparEntrada());

            tela = moldura("Etapa 2 de 3 – Senha pessoal de " + u.email
                    + (u.errosSenha > 0 ? "  (" + u.errosSenha + " erro(s) consecutivo(s))" : ""), c);
            redistribuir();
            atualizarVisor();
        }

        void redistribuir() {
            List<Integer> d = new ArrayList<>();
            for (int i = 0; i <= 9; i++) d.add(i);
            Collections.shuffle(d, CryptoUtil.random());
            for (int i = 0; i < 5; i++) {
                distribuicao[i][0] = d.get(2 * i);
                distribuicao[i][1] = d.get(2 * i + 1);
                teclas[i].setText(distribuicao[i][0] + " " + distribuicao[i][1]);
            }
        }

        void pressionar(int idx) {
            if (pressionados.size() >= 10) {
                status.setText("A senha pessoal tem no máximo 10 números.");
                return;
            }
            pressionados.add(new int[] {distribuicao[idx][0], distribuicao[idx][1]});
            redistribuir();
            atualizarVisor();
        }

        void limparEntrada() {
            for (int[] p : pressionados) Arrays.fill(p, -1);
            pressionados.clear();
            redistribuir();
            atualizarVisor();
        }

        void atualizarVisor() {
            visor.setText(pressionados.isEmpty() ? "–" : "●".repeat(pressionados.size()));
            if (pressionados.size() < 8)
                status.setText("Digite de 8 a 10 números (" + pressionados.size() + " digitados).");
            else
                status.setText(pressionados.size() + " números digitados. Pressione OK.");
        }

        void habilitar(boolean on) {
            for (JButton b : teclas) b.setEnabled(on);
            ok.setEnabled(on);
            limpar.setEnabled(on);
        }

        void verificar() {
            if (pressionados.size() < 8) {
                Ui.aviso(app, "A senha pessoal é formada por 8, 9 ou 10 números.");
                return;
            }
            final List<int[]> pares = new ArrayList<>(pressionados);
            habilitar(false);
            status.setText("Verificando senha pessoal...");
            app.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

            new SwingWorker<char[], Void>() {
                @Override
                protected char[] doInBackground() {
                    return AuthService.encontrarSenha(u.senhaHash, pares);
                }

                @Override
                protected void done() {
                    app.setCursor(Cursor.getDefaultCursor());
                    char[] senha;
                    try { senha = get(); } catch (Exception ex) { senha = null; }
                    limparEntrada();
                    Sessao s = app.sessao();
                    try {
                        if (senha != null) {
                            s.auth.registrarSenhaOk(u);
                            app.mostrarEtapa3(u, senha);
                            return;
                        }
                        AuthService.ResultadoEtapa2 r = s.auth.registrarErroSenha(u);
                        if (r == AuthService.ResultadoEtapa2.BLOQUEADO) {
                            s.reg.log(Mensagens.AUT2_ENCERRADA, u);
                            Ui.erro(app, "Senha pessoal inválida. Terceiro erro consecutivo.\n"
                                    + "O acesso de " + u.email + " foi bloqueado por 2 minutos.");
                            app.mostrarEtapa1();
                        } else {
                            Ui.erro(app, "Senha pessoal inválida (" + u.errosSenha + "º erro).\n"
                                    + "Após 3 erros consecutivos o acesso será bloqueado por 2 minutos.");
                            habilitar(true);
                        }
                    } catch (Exception ex) {
                        Ui.erro(app, "Erro na verificação da senha: " + ex.getMessage());
                        habilitar(true);
                    }
                }
            }.execute();
        }
    }

    static JPanel etapa3(CofreDigital app, Database.Usuario u, char[] senha) {
        Sessao s = app.sessao();
        JTextField totp = new JTextField(8);
        totp.setFont(Ui.FONTE_TECLA.deriveFont(20f));
        Ui.limitar(totp, 6);
        JButton ok = Ui.botao("OK");
        JButton limpar = Ui.botao("LIMPAR");

        JPanel c = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 0, 4, 8);
        g.anchor = GridBagConstraints.WEST;
        JLabel l = new JLabel("TOTP:");
        l.setFont(Ui.FONTE_NEGRITO);
        c.add(l, g);
        g.gridx = 1;
        c.add(totp, g);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botoes.setOpaque(false);
        botoes.add(ok);
        botoes.add(limpar);
        g.gridx = 0; g.gridy = 1; g.gridwidth = 2; g.anchor = GridBagConstraints.EAST;
        g.insets = new Insets(14, 0, 0, 0);
        c.add(botoes, g);
        JLabel dica = new JLabel("Informe o código de 6 dígitos do Google Authenticator.");
        dica.setFont(Ui.FONTE.deriveFont(12f));
        dica.setForeground(Ui.SUAVE);
        g.gridy = 2; g.anchor = GridBagConstraints.WEST;
        c.add(dica, g);

        Runnable enviar = () -> {
            try {
                if (AuthService.validarToken(u.tokenKeyCifrada, senha, totp.getText())) {
                    Arrays.fill(senha, '\0');
                    s.auth.registrarTokenOk(u);
                    app.autenticado(u);
                    return;
                }
                AuthService.ResultadoEtapa2 r = s.auth.registrarErroToken(u);
                if (r == AuthService.ResultadoEtapa2.BLOQUEADO) {
                    Arrays.fill(senha, '\0');
                    s.reg.log(Mensagens.AUT3_ENCERRADA, u);
                    Ui.erro(app, "Token inválido. Terceiro erro consecutivo.\n"
                            + "O acesso de " + u.email + " foi bloqueado por 2 minutos.");
                    app.mostrarEtapa1();
                    return;
                }
                Ui.erro(app, "Token inválido (" + u.errosToken + "º erro).\n"
                        + "Após 3 erros consecutivos o acesso será bloqueado por 2 minutos.");
                totp.setText("");
                totp.requestFocusInWindow();
            } catch (Exception ex) {
                Ui.erro(app, "Erro na verificação do token: " + ex.getMessage());
            }
        };
        ok.addActionListener(e -> enviar.run());
        totp.addActionListener(e -> enviar.run());
        limpar.addActionListener(e -> { totp.setText(""); totp.requestFocusInWindow(); });

        JPanel tela = moldura("Etapa 3 de 3 – Token de " + u.email, c);
        SwingUtilities.invokeLater(totp::requestFocusInWindow);
        return tela;
    }
}
