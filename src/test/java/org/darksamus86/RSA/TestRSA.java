package org.darksamus86.RSA;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class TestRSA {

    @Test
    void testKeyGenerationFormat() {
        String[] keys = RSA.generateKeys();
        assertEquals(2, keys.length, "generateKeys() должен возвращать массив из двух строк");

        assertTrue(keys[0].contains(","),
                "Открытый ключ должен быть формата e,n");

        assertTrue(keys[1].contains(","),
                "Закрытый ключ должен быть формата d,n");
    }

    @Test
    void testEncryptDecryptBasic() {
        String[] keys = RSA.generateKeys();
        String publicKey = keys[0];   // "e,n"
        String privateKey = keys[1];  // "d,n"

        long e = Long.parseLong(publicKey.split(",")[0]);
        long n = Long.parseLong(publicKey.split(",")[1]);
        long d = Long.parseLong(privateKey.split(",")[0]);

        String message = "Hello RSA";

        String encrypted = RSA.encrypt(message, e, n);
        String decrypted = RSA.decrypt(encrypted, d, n);

        assertEquals(message, decrypted, "RSA.encrypt → RSA.decrypt должны давать исходное сообщение");
    }

    @Test
    void testDifferentMessagesHaveDifferentCipher() {
        String[] keys = RSA.generateKeys();
        long e = Long.parseLong(keys[0].split(",")[0]);
        long n = Long.parseLong(keys[0].split(",")[1]);

        String msg1 = "A";
        String msg2 = "B";

        String c1 = RSA.encrypt(msg1, e, n);
        String c2 = RSA.encrypt(msg2, e, n);

        assertNotEquals(c1, c2, "Разные сообщения должны шифроваться по-разному");
    }

    @Test
    void testSignWithPrivateVerifyWithPublic() {
        String[] keys = RSA.generateKeys();
        long e = Long.parseLong(keys[0].split(",")[0]);
        long n = Long.parseLong(keys[0].split(",")[1]);
        long d = Long.parseLong(keys[1].split(",")[0]);

        String hash = "0101010101010101";

        // "подпись": шифруем приватным ключом
        String signature = RSA.encrypt(hash, d, n);

        // проверка: расшифровка публичным
        String decrypted = RSA.decrypt(signature, e, n);

        assertEquals(hash, decrypted,
                "Шифрование d и расшифрование e должны восстанавливать исходные данные");
    }

    @Test
    void testModInverseCorrectness() {
        long e = 17;
        long phi = 3120;

        // d должно быть 2753
        long d = invokeModInverse(e, phi);

        assertEquals(2753, d, "modInverse(e, phi) должно возвращать корректное d");
    }

    // доступ к private RSA.modInverse() через рефлексию
    private long invokeModInverse(long e, long phi) {
        try {
            var method = RSA.class.getDeclaredMethod("modInverse", long.class, long.class);
            method.setAccessible(true);
            return (long) method.invoke(null, e, phi);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Test
    void testModPowMatchesMathPowModulo() {
        long base = 7;
        long exp = 13;
        long mod = 101;

        long expected = (long) Math.pow(base, exp) % mod;
        long actual = invokeModPow(base, exp, mod);

        assertEquals(expected, actual,
                "modPow должен совпадать с Math.pow(base, exp) % mod для малых чисел");
    }

    // доступ к private RSA.modPow()
    private long invokeModPow(long base, long exp, long mod) {
        try {
            var method = RSA.class.getDeclaredMethod("modPow", long.class, long.class, long.class);
            method.setAccessible(true);
            return (long) method.invoke(null, base, exp, mod);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Test
    void testGcd() {
        long gcd = invokeGcd(48, 18);
        assertEquals(6, gcd, "gcd(48,18) должно быть 6");
    }

    private int invokeGcd(int a, int b) {
        try {
            var method = RSA.class.getDeclaredMethod("gcd", int.class, int.class);
            method.setAccessible(true);
            return (int) method.invoke(null, a, b);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }
}
