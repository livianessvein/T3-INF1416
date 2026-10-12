package cofre;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Date;

/**
 * Time-based One-Time Password (RFC 6238), sobre HOTP (RFC 4226) com
 * segredo codificado em BASE32 (RFC 4648).
 *
 * Implementação própria usando APENAS as classes de apoio
 * javax.crypto.Mac, javax.crypto.spec.SecretKeySpec, java.util.Date e Base32,
 * conforme exigido pelo enunciado.
 */
public class TOTP {
    private byte [] key = null;
    private long timeStepInSeconds = 30;

    // Construtor da classe. Recebe a chave secreta em BASE32 e o intervalo
    // de tempo a ser adotado (default = 30 segundos). Deve decodificar a
    // chave secreta e armazenar em key. Em caso de erro, gera Exception.
    public TOTP(String base32EncodedSecret, long timeStepInSeconds)
    throws Exception {
        if (base32EncodedSecret == null || base32EncodedSecret.trim().isEmpty())
            throw new Exception("Segredo TOTP ausente.");
        if (timeStepInSeconds <= 0)
            throw new Exception("Intervalo de tempo do TOTP inválido.");

        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        // Remove eventual padding '=' para aceitar as duas formas de exportação.
        String semPadding = base32EncodedSecret.trim().replace("=", "");
        byte[] decoded = base32.fromString(semPadding);
        if (decoded == null || decoded.length == 0)
            throw new Exception("Segredo TOTP não está em BASE32 válido.");

        this.key = decoded;
        this.timeStepInSeconds = timeStepInSeconds;
    }

    public TOTP(String base32EncodedSecret) throws Exception {
        this(base32EncodedSecret, 30);
    }

    // Recebe o HASH HMAC-SHA1 e determina o código TOTP de 6 algarismos
    // decimais, prefixado com zeros quando necessário.
    private String getTOTPCodeFromHash(byte[] hash) {
        // Truncamento dinâmico (RFC 4226, seção 5.3): os 4 bits menos
        // significativos do último byte indicam o deslocamento.
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset]     & 0x7F) << 24)
                   | ((hash[offset + 1] & 0xFF) << 16)
                   | ((hash[offset + 2] & 0xFF) << 8)
                   |  (hash[offset + 3] & 0xFF);
        int otp = binary % 1000000;

        StringBuilder sb = new StringBuilder(Integer.toString(otp));
        while (sb.length() < 6)
            sb.insert(0, '0');
        return sb.toString();
    }

    // Recebe o contador e a chave secreta para produzir o hash HMAC-SHA1.
    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
            return mac.doFinal(counter);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao calcular HMAC-SHA1: " + e.getMessage());
        }
    }

    // Recebe o intervalo de tempo e executa o algoritmo TOTP para produzir
    // o código TOTP. Usa os métodos auxiliares getTOTPCodeFromHash e HMAC_SHA1.
    private String TOTPCode(long timeInterval) {
        // Contador de 8 bytes em big-endian (RFC 4226, seção 5.1).
        byte[] counter = new byte[8];
        long value = timeInterval;
        for (int i = 7; i >= 0; i--) {
            counter[i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
        byte[] hash = HMAC_SHA1(counter, key);
        return getTOTPCodeFromHash(hash);
    }

    // Quantidade de intervalos de timeStepInSeconds desde 01/01/1970 00:00:00 GMT.
    private long currentInterval() {
        return (new Date().getTime() / 1000L) / timeStepInSeconds;
    }

    // Método que é utilizado para solicitar a geração do código TOTP.
    public String generateCode() {
        return TOTPCode(currentInterval());
    }

    // Método que é utilizado para validar um código TOTP (inputTOTP).
    // Deve considerar um atraso ou adiantamento de 30 segundos no
    // relógio da máquina que gerou o código TOTP.
    public boolean validateCode(String inputTOTP) {
        if (inputTOTP == null)
            return false;
        String code = inputTOTP.trim();
        if (code.length() != 6)
            return false;
        for (int i = 0; i < code.length(); i++)
            if (code.charAt(i) < '0' || code.charAt(i) > '9')
                return false;

        long t = currentInterval();
        // (i) intervalo atual, (ii) um intervalo a menos, (iii) um intervalo a mais.
        String atual = TOTPCode(t);
        String anterior = TOTPCode(t - 1);
        String posterior = TOTPCode(t + 1);

        // Compara todos os valores (sem curto-circuito) para não vazar tempo.
        boolean ok = constantTimeEquals(atual, code);
        ok |= constantTimeEquals(anterior, code);
        ok |= constantTimeEquals(posterior, code);
        return ok;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length())
            return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++)
            diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }
}
