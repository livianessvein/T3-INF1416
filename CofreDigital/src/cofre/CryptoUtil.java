package cofre;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * Operações criptográficas do Cofre Digital.
 *
 *  - Chave AES-256 derivada de uma semente (frase secreta, senha pessoal ou
 *    semente do envelope digital) via SHA1PRNG + KeyGenerator.
 *  - AES/ECB/PKCS5Padding para chave privada, segredo TOTP e arquivos.
 *  - RSA/ECB/PKCS1Padding para abrir envelopes digitais.
 *  - SHA1withRSA para assinaturas digitais.
 *  - bcrypt 2y custo 8 (OpenBSDBCrypt do BouncyCastle) para a senha pessoal.
 */
public final class CryptoUtil {

    public static final String AES_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    public static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    public static final String SIGNATURE_ALG = "SHA1withRSA";
    public static final String BCRYPT_VERSION = "2y";
    public static final int BCRYPT_COST = 8;

    private static final SecureRandom RANDOM = new SecureRandom();

    private CryptoUtil() {}

    /** Erro específico de validação da chave privada (mapeia os códigos 6005/6006/6007). */
    public static class KeyValidationException extends Exception {
        public enum Motivo { CAMINHO_INVALIDO, FRASE_INVALIDA, ASSINATURA_INVALIDA }
        public final Motivo motivo;
        public KeyValidationException(Motivo motivo, String msg) {
            super(msg);
            this.motivo = motivo;
        }
    }

    // ------------------------------------------------------------------
    // AES com chave gerada por SHA1PRNG
    // ------------------------------------------------------------------

    /** Gera a chave AES de 256 bits a partir de uma semente usando SHA1PRNG. */
    public static SecretKey aesKeyFromSeed(byte[] seed) throws GeneralSecurityException {
        SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
        prng.setSeed(seed);
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, prng);
        return kg.generateKey();
    }

    public static SecretKey aesKeyFromSecret(char[] secret) throws GeneralSecurityException {
        byte[] seed = toUtf8(secret);
        try {
            return aesKeyFromSeed(seed);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    public static byte[] aesEncrypt(byte[] plain, SecretKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION);
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plain);
    }

    public static byte[] aesDecrypt(byte[] cipherText, SecretKey key) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(cipherText);
    }

    // ------------------------------------------------------------------
    // Chave privada e certificado
    // ------------------------------------------------------------------

    /**
     * Decripta o arquivo binário da chave privada (AES/ECB/PKCS5, chave via
     * SHA1PRNG da frase secreta) e restaura o objeto PrivateKey (PKCS8 BASE64).
     */
    public static PrivateKey decryptPrivateKey(byte[] encryptedKey, char[] fraseSecreta)
            throws KeyValidationException {
        byte[] pemBytes = null;
        try {
            SecretKey k = aesKeyFromSecret(fraseSecreta);
            try {
                pemBytes = aesDecrypt(encryptedKey, k);
            } catch (BadPaddingException e) {
                throw new KeyValidationException(KeyValidationException.Motivo.FRASE_INVALIDA,
                        "Frase secreta inválida para a chave privada.");
            }
            String pem = new String(pemBytes, StandardCharsets.US_ASCII);
            if (!pem.contains("-----BEGIN PRIVATE KEY-----"))
                throw new KeyValidationException(KeyValidationException.Motivo.FRASE_INVALIDA,
                        "Frase secreta inválida para a chave privada.");
            String b64 = pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "")
                            .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(b64);
            try {
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
                return KeyFactory.getInstance("RSA").generatePrivate(spec);
            } finally {
                Arrays.fill(der, (byte) 0);
            }
        } catch (KeyValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyValidationException(KeyValidationException.Motivo.FRASE_INVALIDA,
                    "Não foi possível restaurar a chave privada: " + e.getMessage());
        } finally {
            if (pemBytes != null) Arrays.fill(pemBytes, (byte) 0);
        }
    }

    /** Restaura um certificado X.509 a partir dos bytes do arquivo (PEM ou DER). */
    public static X509Certificate loadCertificate(byte[] certBytes) throws GeneralSecurityException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
    }

    /** Converte o certificado para PEM (apenas o bloco BEGIN/END CERTIFICATE). */
    public static String toPem(X509Certificate cert) throws GeneralSecurityException {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                           .encodeToString(cert.getEncoded());
        return "-----BEGIN CERTIFICATE-----\n" + b64 + "\n-----END CERTIFICATE-----\n";
    }

    public static X509Certificate fromPem(String pem) throws GeneralSecurityException {
        return loadCertificate(pem.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Testa o par de chaves: assina um array aleatório de {@code size} bytes
     * com a chave privada e verifica a assinatura com a chave pública do certificado.
     */
    public static boolean validateKeyPair(PrivateKey priv, PublicKey pub, int size) {
        try {
            byte[] data = new byte[size];
            RANDOM.nextBytes(data);
            Signature signer = Signature.getInstance(SIGNATURE_ALG);
            signer.initSign(priv);
            signer.update(data);
            byte[] sig = signer.sign();

            Signature verifier = Signature.getInstance(SIGNATURE_ALG);
            verifier.initVerify(pub);
            verifier.update(data);
            return verifier.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    /** Decripta a chave privada e valida contra o certificado (10240 bytes no cofre). */
    public static PrivateKey loadAndValidatePrivateKey(byte[] encryptedKey, char[] frase,
                                                       X509Certificate cert, int testSize)
            throws KeyValidationException {
        PrivateKey pk = decryptPrivateKey(encryptedKey, frase);
        if (!validateKeyPair(pk, cert.getPublicKey(), testSize))
            throw new KeyValidationException(KeyValidationException.Motivo.ASSINATURA_INVALIDA,
                    "A chave privada não corresponde à chave pública do certificado.");
        return pk;
    }

    // ------------------------------------------------------------------
    // Envelope e assinatura digital
    // ------------------------------------------------------------------

    /** Abre o envelope digital (RSA/ECB/PKCS1) e devolve a semente SHA1PRNG. */
    public static byte[] openEnvelope(byte[] envelope, PrivateKey priv) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(RSA_TRANSFORMATION);
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal(envelope);
    }

    public static boolean verifySignature(byte[] data, byte[] signature, PublicKey pub) {
        try {
            Signature v = Signature.getInstance(SIGNATURE_ALG);
            v.initVerify(pub);
            v.update(data);
            return v.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // bcrypt
    // ------------------------------------------------------------------

    public static String bcryptHash(char[] senha) {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return OpenBSDBCrypt.generate(BCRYPT_VERSION, senha, salt, BCRYPT_COST);
    }

    public static boolean bcryptCheck(String stored, char[] senha) {
        try {
            return OpenBSDBCrypt.checkPassword(stored, senha);
        } catch (Exception e) {
            return false;
        }
    }

    // ------------------------------------------------------------------
    // Utilidades
    // ------------------------------------------------------------------

    public static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    public static SecureRandom random() {
        return RANDOM;
    }

    public static byte[] toUtf8(char[] chars) {
        java.nio.ByteBuffer bb = StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        byte[] out = new byte[bb.remaining()];
        bb.get(out);
        if (bb.hasArray()) Arrays.fill(bb.array(), (byte) 0);
        return out;
    }

    /** Extrai um atributo (CN, E, ...) de um nome X.500. */
    public static String dnAttribute(javax.security.auth.x500.X500Principal p,
                                     org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
        X500Name name = X500Name.getInstance(p.getEncoded());
        RDN[] rdns = name.getRDNs(oid);
        if (rdns == null || rdns.length == 0)
            return null;
        ASN1Encodable v = rdns[0].getFirst().getValue();
        return IETFUtils.valueToString(v);
    }

    public static String subjectCN(X509Certificate c) {
        return dnAttribute(c.getSubjectX500Principal(), BCStyle.CN);
    }

    public static String subjectEmail(X509Certificate c) {
        return dnAttribute(c.getSubjectX500Principal(), BCStyle.E);
    }

    public static String issuerCN(X509Certificate c) {
        return dnAttribute(c.getIssuerX500Principal(), BCStyle.CN);
    }

    /** DN legível, com rótulo EMAILADDRESS para o OID 1.2.840.113549.1.9.1. */
    public static String readableDN(javax.security.auth.x500.X500Principal p) {
        return p.getName(javax.security.auth.x500.X500Principal.RFC1779,
                java.util.Map.of("1.2.840.113549.1.9.1", "EMAILADDRESS"));
    }
}
