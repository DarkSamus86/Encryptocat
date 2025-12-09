package org.darksamus86.RSA;

public class TestRSA {

    public static void main(String[] args) {

        testKeyGeneration();
        testEncryptDecryptSimple();
        testEncryptDecryptWithSymbols();
        testMultipleMessages();
        testDifferentKeysIndependence();
    }

    // --- Тест 1: генерация ключей ---
    private static void testKeyGeneration() {
        System.out.println("== Тест 1: Генерация ключей ==");

        String[] keys = RSA.generateKeys();
        String publicKey = keys[0];
        String privateKey = keys[1];

        if (!publicKey.contains(",") || !privateKey.contains(",")) {
            System.out.println("❌ Ошибка: формат ключей неверный!");
            return;
        }

        System.out.println("✔ Ключи успешно сгенерированы\n");
    }

    // --- Тест 2: простое шифрование/дешифрование ---
    private static void testEncryptDecryptSimple() {
        System.out.println("== Тест 2: Простое шифрование/дешифрование ==");

        String[] keys = RSA.generateKeys();
        String[] pub = keys[0].split(",");
        String[] priv = keys[1].split(",");

        long e = Long.parseLong(pub[0]);
        long n = Long.parseLong(pub[1]);
        long d = Long.parseLong(priv[0]);

        String msg = "Hello";
        String encrypted = RSA.encrypt(msg, e, n);
        String decrypted = RSA.decrypt(encrypted, d, n);

        System.out.println("Зашифровано: " + encrypted);
        System.out.println("Расшифровано: " + decrypted);

        if (!msg.equals(decrypted)) {
            System.out.println("❌ Ошибка: расшифрование неверное!");
        } else {
            System.out.println("✔ Шифрование работает корректно\n");
        }
    }

    // --- Тест 3: текст с пробелами и знаками ---
    private static void testEncryptDecryptWithSymbols() {
        System.out.println("== Тест 3: Шифрование текста со знаками ==");

        String[] keys = RSA.generateKeys();
        String[] pub = keys[0].split(",");
        String[] priv = keys[1].split(",");

        long e = Long.parseLong(pub[0]);
        long n = Long.parseLong(pub[1]);
        long d = Long.parseLong(priv[0]);

        String msg = "Hello, World! 123";
        String encrypted = RSA.encrypt(msg, e, n);
        String decrypted = RSA.decrypt(encrypted, d, n);

        System.out.println("Расшифровано: " + decrypted);

        if (!msg.equals(decrypted)) {
            System.out.println("❌ Ошибка: неверный результат!");
        } else {
            System.out.println("✔ Символы корректно шифруются\n");
        }
    }

    // --- Тест 4: несколько сообщений подряд ---
    private static void testMultipleMessages() {
        System.out.println("== Тест 4: Несколько сообщений ==");

        String[] keys = RSA.generateKeys();
        String[] pub = keys[0].split(",");
        String[] priv = keys[1].split(",");

        long e = Long.parseLong(pub[0]);
        long n = Long.parseLong(pub[1]);
        long d = Long.parseLong(priv[0]);

        String[] messages = {
                "Hi",
                "Test message",
                "12345",
                "!@#$%^&*()"
        };

        boolean ok = true;

        for (String msg : messages) {
            String encrypted = RSA.encrypt(msg, e, n);
            String decrypted = RSA.decrypt(encrypted, d, n);
            if (!msg.equals(decrypted)) ok = false;
        }

        if (!ok) {
            System.out.println("❌ Ошибка: одно из сообщений не расшифровалось");
        } else {
            System.out.println("✔ Все сообщения успешно шифруются/дешифруются\n");
        }
    }

    // --- Тест 5: независимость разных пар ключей ---
    private static void testDifferentKeysIndependence() {
        System.out.println("== Тест 5: Независимость ключей ==");

        String[] keys1 = RSA.generateKeys();
        String[] keys2 = RSA.generateKeys();

        long e1 = Long.parseLong(keys1[0].split(",")[0]);
        long n1 = Long.parseLong(keys1[0].split(",")[1]);
        long d1 = Long.parseLong(keys1[1].split(",")[0]);

        long e2 = Long.parseLong(keys2[0].split(",")[0]);
        long n2 = Long.parseLong(keys2[0].split(",")[1]);
        long d2 = Long.parseLong(keys2[1].split(",")[0]);

        String msg = "RSA Test";

        String encrypted1 = RSA.encrypt(msg, e1, n1);
        String decrypted2 = RSA.decrypt(encrypted1, d2, n2);

        if (msg.equals(decrypted2)) {
            System.out.println("❌ Ошибка: разные ключи не должны подходить!");
        } else {
            System.out.println("✔ Разные пары ключей независимы\n");
        }
    }
}
