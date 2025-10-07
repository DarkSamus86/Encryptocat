package org.darksamus86.EDS;

import org.darksamus86.Hash.Hash;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Класс EDS — реализация электронной цифровой подписи,
 * использующая собственный 32-битный хеш (Hash.hash)
 * и RSA с алгоритмом "SHA256withRSA".
 */
public class EDS {
    private final KeyPair keyPair;

    // фиксированный IV для хеш-функции
    private static final String FIXED_IV_HEX = "0x12345678";

    // ---------------- Конструктор ----------------
    public EDS() throws NoSuchAlgorithmException {
        this.keyPair = generateRsaKeys();
    }

    private static KeyPair generateRsaKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    // ---------------- Геттеры ключей ----------------
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    // ---------------- Вспомогательные методы ----------------
    private byte[] computeHashBytesFromInputString(String input) {
        String bits = Hash.hash(FIXED_IV_HEX, input);
        if (bits == null) throw new IllegalStateException("Hash.hash вернул null");

        if (bits.length() != 32) {
            // выравниваем длину
            if (bits.length() < 32) bits = String.format("%32s", bits).replace(' ', '0');
            else bits = bits.substring(bits.length() - 32);
        }

        long value = Long.parseLong(bits, 2);
        byte[] out = new byte[4];
        out[0] = (byte) ((value >>> 24) & 0xFF);
        out[1] = (byte) ((value >>> 16) & 0xFF);
        out[2] = (byte) ((value >>> 8) & 0xFF);
        out[3] = (byte) (value & 0xFF);
        return out;
    }

    // ---------------- Подпись и проверка ----------------
    public byte[] signMessage(String message) throws GeneralSecurityException {
        byte[] hashBytes = computeHashBytesFromInputString(message);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(hashBytes);
        return sig.sign();
    }

    public boolean verifyMessage(String message, byte[] signature) throws GeneralSecurityException {
        byte[] hashBytes = computeHashBytesFromInputString(message);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(keyPair.getPublic());
        sig.update(hashBytes);
        return sig.verify(signature);
    }

    // ---------------- Утилиты для PEM и HEX ----------------
    public String getPublicKeyPem() {
        byte[] der = keyPair.getPublic().getEncoded();
        return wrapPem("PUBLIC KEY", Base64.getEncoder().encodeToString(der));
    }

    public String getPrivateKeyPem() {
        byte[] der = keyPair.getPrivate().getEncoded();
        return wrapPem("PRIVATE KEY", Base64.getEncoder().encodeToString(der));
    }

    private static String wrapPem(String type, String base64) {
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(type).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            int end = Math.min(i + 64, base64.length());
            sb.append(base64, i, end).append('\n');
        }
        sb.append("-----END ").append(type).append("-----\n");
        return sb.toString();
    }

    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static byte[] fromHex(String hex) {
        String s = hex.trim();
        if (s.length() % 2 != 0) s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int index = i * 2;
            out[i] = (byte) Integer.parseInt(s.substring(index, index + 2), 16);
        }
        return out;
    }

    // ---------------- Конвертация PEM <-> ключи ----------------
    public static PublicKey pemToPublicKey(String pem) throws GeneralSecurityException {
        String body = pem.replaceAll("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    public static PrivateKey pemToPrivateKey(String pem) throws GeneralSecurityException {
        String body = pem.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(body);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
}
