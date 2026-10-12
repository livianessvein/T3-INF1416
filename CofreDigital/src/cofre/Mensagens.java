package cofre;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Tabela de Mensagens de Registro (anexo do enunciado). Os textos são
 * gravados apenas na tabela Mensagens; a tabela Registros guarda só o MID.
 */
public final class Mensagens {

    private Mensagens() {}

    public static final int SISTEMA_INICIADO = 1001;
    public static final int SISTEMA_ENCERRADO = 1002;
    public static final int SESSAO_INICIADA = 1003;
    public static final int SESSAO_ENCERRADA = 1004;
    public static final int PARTIDA_CADASTRO_ADMIN = 1005;
    public static final int PARTIDA_OPERACAO_NORMAL = 1006;

    public static final int AUT1_INICIADA = 2001;
    public static final int AUT1_ENCERRADA = 2002;
    public static final int LOGIN_LIBERADO = 2003;
    public static final int LOGIN_BLOQUEADO = 2004;
    public static final int LOGIN_NAO_IDENTIFICADO = 2005;

    public static final int AUT2_INICIADA = 3001;
    public static final int AUT2_ENCERRADA = 3002;
    public static final int SENHA_OK = 3003;
    public static final int SENHA_ERRO1 = 3004;
    public static final int SENHA_ERRO2 = 3005;
    public static final int SENHA_ERRO3 = 3006;
    public static final int SENHA_BLOQUEIO = 3007;

    public static final int AUT3_INICIADA = 4001;
    public static final int AUT3_ENCERRADA = 4002;
    public static final int TOKEN_OK = 4003;
    public static final int TOKEN_ERRO1 = 4004;
    public static final int TOKEN_ERRO2 = 4005;
    public static final int TOKEN_ERRO3 = 4006;
    public static final int TOKEN_BLOQUEIO = 4007;

    public static final int TELA_PRINCIPAL = 5001;
    public static final int MENU_OPCAO1 = 5002;
    public static final int MENU_OPCAO2 = 5003;
    public static final int MENU_OPCAO3 = 5004;

    public static final int TELA_CADASTRO = 6001;
    public static final int CAD_BOTAO_CADASTRAR = 6002;
    public static final int CAD_SENHA_INVALIDA = 6003;
    public static final int CAD_CERT_INVALIDO = 6004;
    public static final int CAD_CHAVE_CAMINHO = 6005;
    public static final int CAD_CHAVE_FRASE = 6006;
    public static final int CAD_CHAVE_ASSINATURA = 6007;
    public static final int CAD_CONFIRMACAO_ACEITA = 6008;
    public static final int CAD_CONFIRMACAO_REJEITADA = 6009;
    public static final int CAD_BOTAO_VOLTAR = 6010;

    public static final int TELA_CONSULTA = 7001;
    public static final int CON_BOTAO_VOLTAR = 7002;
    public static final int CON_BOTAO_LISTAR = 7003;
    public static final int CON_PASTA_INVALIDA = 7004;
    public static final int INDEX_DECRIPTADO = 7005;
    public static final int INDEX_VERIFICADO = 7006;
    public static final int INDEX_FALHA_DECRIPTACAO = 7007;
    public static final int INDEX_FALHA_VERIFICACAO = 7008;
    public static final int INDEX_LISTA_APRESENTADA = 7009;
    public static final int SHARE_DECRIPTADO = 7010;
    public static final int SHARE_VERIFICADO = 7011;
    public static final int SHARE_FALHA_DECRIPTACAO = 7012;
    public static final int SHARE_FALHA_VERIFICACAO = 7013;
    public static final int SHARE_LISTA_APRESENTADA = 7014;
    public static final int ARQ_SELECIONADO = 7015;
    public static final int ARQ_ACESSO_PERMITIDO = 7016;
    public static final int ARQ_ACESSO_NEGADO = 7017;
    public static final int ARQ_DECRIPTADO = 7018;
    public static final int ARQ_VERIFICADO = 7019;
    public static final int ARQ_FALHA_DECRIPTACAO = 7020;
    public static final int ARQ_FALHA_VERIFICACAO = 7021;

    public static final int TELA_SAIDA = 8001;
    public static final int SAI_ENCERRAR_SESSAO = 8002;
    public static final int SAI_ENCERRAR_SISTEMA = 8003;
    public static final int SAI_BOTAO_VOLTAR = 8004;

    public static final Map<Integer, String> TODAS;

    static {
        Map<Integer, String> m = new LinkedHashMap<>();
        m.put(1001, "Sistema iniciado.");
        m.put(1002, "Sistema encerrado.");
        m.put(1003, "Sessão iniciada para <login_name>.");
        m.put(1004, "Sessão encerrada para <login_name>.");
        m.put(1005, "Partida do sistema iniciada para cadastro do administrador.");
        m.put(1006, "Partida do sistema iniciada para operação normal pelos usuários.");
        m.put(2001, "Autenticação etapa 1 iniciada.");
        m.put(2002, "Autenticação etapa 1 encerrada.");
        m.put(2003, "Login name <login_name> identificado com acesso liberado.");
        m.put(2004, "Login name <login_name> identificado com acesso bloqueado.");
        m.put(2005, "Login name <login_name> não identificado.");
        m.put(3001, "Autenticação etapa 2 iniciada para <login_name>.");
        m.put(3002, "Autenticação etapa 2 encerrada para <login_name>.");
        m.put(3003, "Senha pessoal verificada positivamente para <login_name>.");
        m.put(3004, "Primeiro erro da senha pessoal contabilizado para <login_name>.");
        m.put(3005, "Segundo erro da senha pessoal contabilizado para <login_name>.");
        m.put(3006, "Terceiro erro da senha pessoal contabilizado para <login_name>.");
        m.put(3007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 2.");
        m.put(4001, "Autenticação etapa 3 iniciada para <login_name>.");
        m.put(4002, "Autenticação etapa 3 encerrada para <login_name>.");
        m.put(4003, "Token verificado positivamente para <login_name>.");
        m.put(4004, "Primeiro erro de token contabilizado para <login_name>.");
        m.put(4005, "Segundo erro de token contabilizado para <login_name>.");
        m.put(4006, "Terceiro erro de token contabilizado para <login_name>.");
        m.put(4007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 3.");
        m.put(5001, "Tela principal apresentada para <login_name>.");
        m.put(5002, "Opção 1 do menu principal selecionada por <login_name>.");
        m.put(5003, "Opção 2 do menu principal selecionada por <login_name>.");
        m.put(5004, "Opção 3 do menu principal selecionada por <login_name>.");
        m.put(6001, "Tela de cadastro apresentada para <login_name>.");
        m.put(6002, "Botão cadastrar pressionado por <login_name>.");
        m.put(6003, "Senha pessoal inválida fornecida por <login_name>.");
        m.put(6004, "Caminho do certificado digital inválido fornecido por <login_name>.");
        m.put(6005, "Chave privada verificada negativamente para <login_name> (caminho inválido).");
        m.put(6006, "Chave privada verificada negativamente para <login_name> (frase secreta inválida).");
        m.put(6007, "Chave privada verificada negativamente para <login_name> (assinatura digital inválida).");
        m.put(6008, "Confirmação de dados aceita por <login_name>.");
        m.put(6009, "Confirmação de dados rejeitada por <login_name>.");
        m.put(6010, "Botão voltar de cadastro para o menu principal pressionado por <login_name>.");
        m.put(7001, "Tela de consulta de arquivos secretos apresentada para <login_name>.");
        m.put(7002, "Botão voltar de consulta para o menu principal pressionado por <login_name>.");
        m.put(7003, "Botão Listar de consulta pressionado por <login_name>.");
        m.put(7004, "Caminho de pasta inválido fornecido por <login_name>.");
        m.put(7005, "Arquivo de índice decriptado com sucesso para <login_name>.");
        m.put(7006, "Arquivo de índice verificado (integridade e autenticidade) com sucesso para <login_name>.");
        m.put(7007, "Falha na decriptação do arquivo de índice para <login_name>.");
        m.put(7008, "Falha na verificação (integridade e autenticidade) do arquivo de índice para <login_name>.");
        m.put(7009, "Lista de arquivos presentes no índice apresentada para <login_name>.");
        m.put(7010, "Arquivo de share decriptado com sucesso para <login_name>.");
        m.put(7011, "Arquivo de share verificado (integridade e autenticidade) com sucesso para <login_name>.");
        m.put(7012, "Falha na decriptação do arquivo de share para <login_name>.");
        m.put(7013, "Falha na verificação (integridade e autenticidade) do arquivo de share para <login_name>.");
        m.put(7014, "Lista de arquivos presentes no share apresentada para <login_name>.");
        m.put(7015, "Arquivo <arq_name> selecionado por <login_name> para decriptação.");
        m.put(7016, "Acesso permitido ao arquivo <arq_name> para <login_name>.");
        m.put(7017, "Acesso negado ao arquivo <arq_name> para <login_name>.");
        m.put(7018, "Arquivo <arq_name> decriptado com sucesso para <login_name>.");
        m.put(7019, "Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>.");
        m.put(7020, "Falha na decriptação do arquivo <arq_name> para <login_name>.");
        m.put(7021, "Falha na verificação (integridade e autenticidade) do arquivo <arq_name> para <login_name>.");
        m.put(8001, "Tela de saída apresentada para <login_name>.");
        m.put(8002, "Botão encerrar sessão pressionado por <login_name>.");
        m.put(8003, "Botão encerrar sistema pressionado por <login_name>.");
        m.put(8004, "Botão voltar de sair para o menu principal pressionado por <login_name>.");
        TODAS = Collections.unmodifiableMap(m);
    }
}
