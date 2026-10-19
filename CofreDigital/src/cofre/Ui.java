/*
 * Livian Essvein - 2211667
 * Breno Lois Matos - 2210780
 */

package cofre;

import javax.swing.*;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

final class Ui {
    private Ui() {}

    static final Color FUNDO = new Color(0xF4F5F7);
    static final Color PAINEL = Color.WHITE;
    static final Color BORDA = new Color(0xD5D9E0);
    static final Color TEXTO = new Color(0x1F2933);
    static final Color SUAVE = new Color(0x5F6B7A);
    static final Color DESTAQUE = new Color(0x1D4E89);
    static final Color ERRO = new Color(0xB42318);

    static final Font FONTE = new Font(Font.SANS_SERIF, Font.PLAIN, 14);
    static final Font FONTE_NEGRITO = FONTE.deriveFont(Font.BOLD);
    static final Font FONTE_TITULO = FONTE.deriveFont(Font.BOLD, 18f);
    static final Font FONTE_TECLA = new Font(Font.MONOSPACED, Font.BOLD, 22);

    static JPanel secao(String titulo, JComponent conteudo) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(PAINEL);
        TitledBorder tb = BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(BORDA), titulo);
        tb.setTitleFont(FONTE.deriveFont(Font.BOLD, 11f));
        tb.setTitleColor(SUAVE);
        p.setBorder(new CompoundBorder(tb, new EmptyBorder(6, 10, 8, 10)));
        conteudo.setOpaque(false);
        p.add(conteudo, BorderLayout.CENTER);
        return p;
    }

    static JPanel cabecalho(Database.Usuario u) {
        JPanel p = new JPanel(new GridLayout(3, 1, 0, 2));
        p.add(rotulo("Login: ", u.email));
        p.add(rotulo("Grupo: ", u.grupoExibicao()));
        p.add(rotulo("Nome: ", u.nome));
        return secao("Cabeçalho", p);
    }

    static JPanel rotulo(String chave, String valor) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        p.setOpaque(false);
        JLabel k = new JLabel(chave);
        k.setFont(FONTE_NEGRITO);
        k.setForeground(TEXTO);
        JLabel v = new JLabel(valor);
        v.setFont(FONTE);
        v.setForeground(TEXTO);
        p.add(k);
        p.add(v);
        return p;
    }

    static JPanel corpo1(String chave, String valor) {
        return secao("Corpo 1", rotulo(chave, valor));
    }

    static JPanel tela(JComponent cab, JComponent c1, JComponent c2) {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBackground(FUNDO);
        p.setBorder(new EmptyBorder(14, 14, 14, 14));
        GridBagConstraints g = new GridBagConstraints();
        g.gridx = 0;
        g.fill = GridBagConstraints.HORIZONTAL;
        g.weightx = 1;
        g.insets = new Insets(0, 0, 10, 0);
        int y = 0;
        if (cab != null) { g.gridy = y++; p.add(cab, g); }
        if (c1 != null) { g.gridy = y++; p.add(c1, g); }
        g.gridy = y;
        g.weighty = 1;
        g.fill = GridBagConstraints.BOTH;
        g.insets = new Insets(0, 0, 0, 0);
        p.add(secao("Corpo 2", c2), g);
        return p;
    }

    static JButton botao(String texto) {
        JButton b = new JButton(texto);
        b.setFont(FONTE);
        b.setFocusPainted(false);
        return b;
    }

    static JLabel titulo(String t) {
        JLabel l = new JLabel(t);
        l.setFont(FONTE_TITULO);
        l.setForeground(DESTAQUE);
        return l;
    }

    static void erro(Component pai, String msg) {
        JOptionPane.showMessageDialog(pai, msg, "Cofre Digital", JOptionPane.ERROR_MESSAGE);
    }

    static void aviso(Component pai, String msg) {
        JOptionPane.showMessageDialog(pai, msg, "Cofre Digital", JOptionPane.WARNING_MESSAGE);
    }

    static void info(Component pai, String msg) {
        JOptionPane.showMessageDialog(pai, msg, "Cofre Digital", JOptionPane.INFORMATION_MESSAGE);
    }

    static void limitar(javax.swing.text.JTextComponent campo, int max) {
        ((javax.swing.text.AbstractDocument) campo.getDocument()).setDocumentFilter(
            new javax.swing.text.DocumentFilter() {
                @Override
                public void insertString(FilterBypass fb, int off, String s, javax.swing.text.AttributeSet a)
                        throws javax.swing.text.BadLocationException {
                    if (s != null && fb.getDocument().getLength() + s.length() <= max)
                        super.insertString(fb, off, s, a);
                }
                @Override
                public void replace(FilterBypass fb, int off, int len, String s, javax.swing.text.AttributeSet a)
                        throws javax.swing.text.BadLocationException {
                    int novo = fb.getDocument().getLength() - len + (s == null ? 0 : s.length());
                    if (novo <= max) super.replace(fb, off, len, s, a);
                }
            });
    }
}
