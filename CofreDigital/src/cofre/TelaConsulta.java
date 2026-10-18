package cofre;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

final class TelaConsulta {
    private final CofreDigital app;
    private final Sessao s;
    private final Database.Usuario u;

    private final JTextField pasta = new JTextField(36);
    private final JPasswordField frase = new JPasswordField(36);
    private final JLabel totalConsultas = new JLabel();
    private final Modelo modelo = new Modelo();
    private final JTable tabela = new JTable(modelo);

    private CofreService.Listagem listagem;
    private PrivateKey chaveUsuario;

    TelaConsulta(CofreDigital app, Database.Usuario u) {
        this.app = app;
        this.s = app.sessao();
        this.u = u;
        Ui.limitar(pasta, 255);
        Ui.limitar(frase, 255);
        s.reg.log(Mensagens.TELA_CONSULTA, u);
    }

    JPanel painel() {
        JPanel c2 = new JPanel(new BorderLayout(0, 10));

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints g = new GridBagConstraints();
        g.anchor = GridBagConstraints.WEST;
        g.insets = new Insets(4, 0, 4, 8);
        JLabel lp = new JLabel("Caminho da pasta:");
        lp.setFont(Ui.FONTE);
        form.add(lp, g);
        g.gridx = 1;
        pasta.setFont(Ui.FONTE);
        form.add(pasta, g);
        g.gridx = 2;
        JButton escolher = Ui.botao("...");
        escolher.setMargin(new Insets(2, 6, 2, 6));
        escolher.addActionListener(e -> {
            JFileChooser fc = new JFileChooser(pasta.getText().isEmpty() ? null : pasta.getText());
            fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            if (fc.showOpenDialog(app) == JFileChooser.APPROVE_OPTION)
                pasta.setText(fc.getSelectedFile().getAbsolutePath());
        });
        form.add(escolher, g);
        g.gridx = 0; g.gridy = 1;
        JLabel lf = new JLabel("Frase secreta:");
        lf.setFont(Ui.FONTE);
        form.add(lf, g);
        g.gridx = 1;
        frase.setFont(Ui.FONTE);
        form.add(frase, g);
        g.gridx = 0; g.gridy = 2; g.gridwidth = 3;
        JButton listar = Ui.botao("Listar");
        listar.addActionListener(e -> listar());
        form.add(listar, g);
        c2.add(form, BorderLayout.NORTH);

        tabela.setFont(Ui.FONTE);
        tabela.setRowHeight(24);
        tabela.getTableHeader().setFont(Ui.FONTE_NEGRITO);
        tabela.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tabela.setFillsViewportHeight(true);
        tabela.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && tabela.getSelectedRow() >= 0)
                    decriptarSelecionado();
            }
        });
        JScrollPane sp = new JScrollPane(tabela);
        sp.setPreferredSize(new Dimension(600, 180));
        c2.add(sp, BorderLayout.CENTER);

        JPanel sul = new JPanel(new BorderLayout(0, 8));
        sul.setOpaque(false);
        JLabel dica = new JLabel("Selecione um arquivo (duplo clique) para decriptá-lo e gravá-lo com o nome secreto.");
        dica.setFont(Ui.FONTE.deriveFont(12f));
        dica.setForeground(Ui.SUAVE);
        sul.add(dica, BorderLayout.NORTH);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        botoes.setOpaque(false);
        JButton decriptar = Ui.botao("Decriptar arquivo selecionado");
        decriptar.addActionListener(e -> decriptarSelecionado());
        JButton voltar = Ui.botao("Voltar de Consultar para o Menu Principal");
        voltar.addActionListener(e -> {
            s.reg.log(Mensagens.CON_BOTAO_VOLTAR, u);
            chaveUsuario = null;
            frase.setText("");
            app.mostrarTelaPrincipal();
        });
        botoes.add(decriptar);
        botoes.add(Box.createHorizontalStrut(8));
        botoes.add(voltar);
        sul.add(botoes, BorderLayout.SOUTH);
        c2.add(sul, BorderLayout.SOUTH);

        JPanel linhaTotal = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        JLabel k = new JLabel("Total de consultas do usuário: ");
        k.setFont(Ui.FONTE_NEGRITO);
        totalConsultas.setFont(Ui.FONTE);
        totalConsultas.setText(String.valueOf(u.numConsultas));
        linhaTotal.add(k);
        linhaTotal.add(totalConsultas);

        return Ui.tela(Ui.cabecalho(u), Ui.secao("Corpo 1", linhaTotal), c2);
    }

    private void listar() {
        s.reg.log(Mensagens.CON_BOTAO_LISTAR, u);
        modelo.definir(new ArrayList<>());
        listagem = null;
        chaveUsuario = null;

        char[] fr = frase.getPassword();
        try {
            if (fr.length == 0) {
                s.reg.log(Mensagens.CAD_CHAVE_FRASE, u);
                Ui.erro(app, "Informe a frase secreta da sua chave privada.");
                return;
            }
            chaveUsuario = CadastroService.chavePrivadaDoUsuario(s.db, u, fr, CadastroService.TAMANHO_TESTE_CHAVE);
        } catch (CryptoUtil.KeyValidationException ex) {
            boolean assinatura = ex.motivo == CryptoUtil.KeyValidationException.Motivo.ASSINATURA_INVALIDA;
            s.reg.log(assinatura ? Mensagens.CAD_CHAVE_ASSINATURA : Mensagens.CAD_CHAVE_FRASE, u);
            Ui.erro(app, assinatura
                    ? "Validação negativa: a chave privada não corresponde ao seu certificado digital."
                    : "Validação negativa: frase secreta inválida.");
            return;
        } catch (Exception ex) {
            Ui.erro(app, "Não foi possível validar a frase secreta: " + ex.getMessage());
            return;
        } finally {
            Arrays.fill(fr, '\0');
        }

        try {
            listagem = s.cofre.listar(pasta.getText(), u, s.chaveAdmin(), s.certAdmin());
        } catch (CofreService.CofreException ex) {
            Ui.erro(app, ex.getMessage());
            return;
        }
        modelo.definir(listagem.entradas);
        totalConsultas.setText(String.valueOf(u.numConsultas));
        if (!listagem.avisos.isEmpty())
            Ui.aviso(app, String.join("\n", listagem.avisos));
        if (listagem.entradas.isEmpty())
            Ui.info(app, "Nenhum arquivo da pasta segura está acessível para " + u.email + ".");
    }

    private void decriptarSelecionado() {
        int row = tabela.getSelectedRow();
        if (listagem == null || row < 0) {
            Ui.aviso(app, "Liste a pasta e selecione um arquivo.");
            return;
        }
        CofreService.Entrada e = modelo.linhas.get(tabela.convertRowIndexToModel(row));
        try {
            CofreService.Resultado r = s.cofre.decriptarArquivo(listagem, e, u, chaveUsuario);
            Ui.info(app, "Arquivo " + e.nomeSecreto + " decriptado e verificado (integridade e autenticidade).\n"
                    + "Gravado em: " + r.arquivoGravado + " (" + r.tamanho + " bytes).");
        } catch (CofreService.CofreException ex) {
            Ui.erro(app, ex.getMessage());
        }
    }

    private static final class Modelo extends AbstractTableModel {
        private static final String[] COLS = {"Nome secreto", "Dono", "Grupo", "Acesso"};
        List<CofreService.Entrada> linhas = new ArrayList<>();

        void definir(List<CofreService.Entrada> l) {
            linhas = l;
            fireTableDataChanged();
        }

        @Override public int getRowCount() { return linhas.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int r, int c) {
            CofreService.Entrada e = linhas.get(r);
            switch (c) {
                case 0: return e.nomeSecreto;
                case 1: return e.dono;
                case 2: return e.grupo;
                default:
                    switch (e.acesso) {
                        case DONO: return "dono";
                        case COMPARTILHADO: return "compartilhado (" + e.idCompartilhamento + ")";
                        default: return "grupo";
                    }
            }
        }
    }
}
