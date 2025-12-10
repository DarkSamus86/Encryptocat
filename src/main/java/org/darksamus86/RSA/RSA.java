package org.darksamus86.RSA;

import java.util.Random;

public class RSA {

    private static int gcd(int a, int b) {
        while (b != 0) {
            int temp = a % b;
            a = b;
            b = temp;
        }
        return a;
    }

    private static boolean isPrime(int n) {
        if (n < 2) return false;
        if (n == 2) return true;
        if (n % 2 == 0) return false;
        for (int i = 3; i * i <= n; i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    }

    private static int generatePrime(int start, int end) {
        Random rand = new Random();
        while (true) {
            int num = rand.nextInt(end - start + 1) + start;
            if (isPrime(num)) return num;
        }
    }

    private static long modInverse(long e, long phi) {
        long[] res = egcd(e, phi);
        if (res[0] != 1) throw new RuntimeException("Обратного элемента не существует");
        return (res[1] % phi + phi) % phi;
    }

    private static long[] egcd(long a, long b) {
        if (a == 0) return new long[]{b, 0, 1};
        long[] res = egcd(b % a, a);
        long g = res[0];
        long x = res[2] - (b / a) * res[1];
        long y = res[1];
        return new long[]{g, x, y};
    }

    private static long modPow(long base, long exp, long mod) {
        long result = 1;
        base %= mod;
        while (exp > 0) {
            if ((exp & 1) == 1) result = (result * base) % mod;
            exp >>= 1;
            base = (base * base) % mod;
        }
        return result;
    }

    public static String[] generateKeys() {
        System.out.println("\nГенерация ключей...");
        int p = generatePrime(100, 300);
        int q = generatePrime(100, 300);
        while (q == p) q = generatePrime(100, 300);

        long n = (long) p * q;
        long phi = (long) (p - 1) * (q - 1);

        Random rand = new Random();
        long e = rand.nextInt((int) phi - 2) + 2;
        while (gcd((int) e, (int) phi) != 1) {
            e = rand.nextInt((int) phi - 2) + 2;
        }

        long d = modInverse(e, phi);

        System.out.println("\n--- Сгенерированные ключи ---");
        System.out.println("p = " + p + ", q = " + q);
        System.out.println("n = " + n);
        System.out.println("φ(n) = " + phi);
        System.out.println("Открытый ключ en = " + e + "," + n);
        System.out.println("Закрытый ключ dn = " + d + "," + n + "\n");

        return new String[]{e + "," + n, d + "," + n};
    }

    public static String encrypt(String message, long e, long n) {
        StringBuilder cipherHex = new StringBuilder();
        for (char ch : message.toCharArray()) {
            long cipherNum = modPow(ch, e, n);
            cipherHex.append(String.format("%08x", cipherNum));
        }
        return cipherHex.toString();
    }

    public static String decrypt(String cipherHex, long d, long n) {
        StringBuilder decrypted = new StringBuilder();
        for (int i = 0; i < cipherHex.length(); i += 8) {
            long num = Long.parseLong(cipherHex.substring(i, i + 8), 16);
            char ch = (char) modPow(num, d, n);
            decrypted.append(ch);
        }
        return decrypted.toString();
    }

    public static void main(String[] args) {
        java.util.Scanner scanner = new java.util.Scanner(System.in);

        // 1. Генерация ключей
        String[] keys = RSA.generateKeys();
        String publicKey = keys[0];   // "e,n"
        String privateKey = keys[1];  // "d,n"

        System.out.println("Публичный ключ:  " + publicKey);
        System.out.println("Приватный ключ:  " + privateKey);
        System.out.println();

        // Разбор ключей
        long e = Long.parseLong(publicKey.split(",")[0]);
        long n = Long.parseLong(publicKey.split(",")[1]);

        long d = Long.parseLong(privateKey.split(",")[0]);
        long n2 = Long.parseLong(privateKey.split(",")[1]); // то же n

        // 2. Ввод сообщения
        System.out.print("Введите текст для шифрования: ");
        String message = scanner.nextLine();

        // 3. Шифрование
        String encrypted = RSA.encrypt(message, e, n);
        System.out.println("\nЗашифрованный текст (HEX):");
        System.out.println(encrypted);

        // 4. Дешифрование
        String decrypted = RSA.decrypt(encrypted, d, n2);
        System.out.println("\nРасшифрованный текст:");
        System.out.println(decrypted);

        // 5. Проверка
        System.out.println("\nПроверка: " + (message.equals(decrypted) ? "Успех" : "Ошибка"));

        scanner.close();
    }

}