package org.darksamus86.EDS;

import org.darksamus86.Hash.Hash;
import org.darksamus86.RSA.RSA;

public class EDS {

    // фиксированный IV для хеш-функции (как у вас было)
    private static final String FIXED_IV_HEX = "0x12345678";

    private final String publicKey;   // формат "e,n"
    private final String privateKey;  // формат "d,n"

    /**
     * Конструктор принимает ключи в том виде, в котором их возвращает RSA.generateKeys():
     * publicKey = "e,n"
     * privateKey = "d,n"
     *
     * Важно: генерация/печать ключей должна выполняться в Main (например, вызовом RSA.generateKeys()),
     * а затем передача строк сюда.
     */
    public EDS(String publicKey, String privateKey) {
        if (publicKey == null || privateKey == null) throw new IllegalArgumentException("Ключи не могут быть null");
        this.publicKey = publicKey.trim();
        this.privateKey = privateKey.trim();
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    // ---------------- Вспомогательные ----------------

    /**
     * Возвращает 32-битную бинарную строку из Hash.hash(FIXED_IV_HEX, message).
     * Если Hash.hash вернёт строку длиннее/короче — нормируем до 32 бит (как в вашей предыдущей реализации).
     */
    private String computeHashBits(String message) {
        String bits = Hash.hash(FIXED_IV_HEX, message);
        if (bits == null) throw new IllegalStateException("Hash.hash вернул null");

        if (bits.length() != 32) {
            if (bits.length() < 32) bits = String.format("%32s", bits).replace(' ', '0');
            else bits = bits.substring(bits.length() - 32);
        }
        return bits;
    }

    /**
     * Разбирает ключ вида "exp,n" -> возвращает long[] {exp, n}
     */
    private long[] parseKeyPair(String key) {
        String s = key.replaceAll("\\s+", "");
        String[] parts = s.split(",");
        if (parts.length != 2) throw new IllegalArgumentException("Некорректный формат ключа: " + key);
        long exp = Long.parseLong(parts[0]);
        long n = Long.parseLong(parts[1]);
        return new long[] { exp, n };
    }

    // ---------------- Подпись и проверка ----------------

    /**
     * Подписывает сообщение: вычисляет хеш (бинарная строка 32 бита),
     * затем "шифрует" эту строку приватным ключом RSA (используя ваш RSA.encrypt),
     * возвращая hex-строку подписи.
     *
     * Метод НЕ печатает ничего.
     */
    public String signMessage(String message) {
        String hashBits = computeHashBits(message); // например "010101..."
        long[] priv = parseKeyPair(privateKey);
        long d = priv[0];
        long n = priv[1];
        // Используем вашу RSA.encrypt: он принимает строку и (e,n) или (d,n).
        // Возвращаем hex-строку, которую генерирует RSA.encrypt
        return RSA.encrypt(hashBits, d, n);
    }

    /**
     * Проверяет подпись: расшифровывает signatureHex публичным ключом (e,n) с помощью RSA.decrypt
     * и сравнивает полученную строку с вычисленным хешем сообщения.
     *
     *
     */
    public boolean verifyMessage(String message, String signatureHex) {
        long[] pub = parseKeyPair(publicKey);
        long e = pub[0];
        long n = pub[1];
        // RSA.decrypt вернёт строку, которая была зашифрована (то есть строку хеша)
        String decrypted = RSA.decrypt(signatureHex, e, n);
        String expectedHash = computeHashBits(message);
        return expectedHash.equals(decrypted);
    }
}
