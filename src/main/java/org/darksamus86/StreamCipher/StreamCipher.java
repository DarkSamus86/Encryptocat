package org.darksamus86.StreamCipher;

import java.util.Scanner;

public class StreamCipher {

    // ------------ Константы как в Python ------------
    static final int R1_LEN = 19;
    static final int R2_LEN = 22;
    static final int R3_LEN = 23;

    static final int[] R1_TAPS = {13, 16, 17, 18};
    static final int[] R2_TAPS = {20, 21};
    static final int[] R3_TAPS = {7, 20, 21, 22};

    static final int R1_SYNC = 8;
    static final int R2_SYNC = 10;
    static final int R3_SYNC = 10;

    // FN в Python было строкой бит
    static final String FN = "11100010010000111001010011101101110001001000";

    // --------------------------------------------------

    static void lfsrShift(int[] reg, int[] taps) {
        int newBit = 0;
        for (int t : taps) newBit ^= reg[t];
        // вставляем в нулевую позицию
        for (int i = reg.length - 1; i > 0; i--)
            reg[i] = reg[i - 1];
        reg[0] = newBit;
    }

    static int majority(int a, int b, int c) {
        return (a & b) | (a & c) | (b & c);
    }

    static int[] strBitsToArray(String bits) {
        int[] arr = new int[bits.length()];
        for (int i = 0; i < bits.length(); i++) {
            arr[i] = bits.charAt(i) - '0';
        }
        return arr;
    }

    static String arrayToBits(int[] arr) {
        StringBuilder sb = new StringBuilder();
        for (int b : arr) sb.append(b);
        return sb.toString();
    }

    static String textToBits(String text) {
        StringBuilder bits = new StringBuilder();
        for (char ch : text.toCharArray()) {
            bits.append(String.format("%8s", Integer.toBinaryString(ch)).replace(' ', '0'));
        }
        return bits.toString();
    }

    static String bitsToText(String bits) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i + 8 <= bits.length(); i += 8) {
            int val = Integer.parseInt(bits.substring(i, i + 8), 2);
            text.append((char) val);
        }
        return text.toString();
    }

    static String bitsToHex(String bits) {
        int pad = (4 - bits.length() % 4) % 4;
        bits = "0".repeat(pad) + bits;
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < bits.length(); i += 4) {
            String nibble = bits.substring(i, i + 4);
            hex.append(Integer.toHexString(Integer.parseInt(nibble, 2)));
        }
        return hex.toString();
    }

    static String hexToBits(String hex) {
        StringBuilder bits = new StringBuilder();
        for (char c : hex.toCharArray()) {
            int val = Integer.parseInt(String.valueOf(c), 16);
            bits.append(String.format("%4s", Integer.toBinaryString(val)).replace(' ', '0'));
        }
        return bits.toString();
    }

    static String generateKey(int bits) {
        StringBuilder sb = new StringBuilder();
        java.util.Random rng = new java.util.Random();
        for (int i = 0; i < bits; i++) sb.append(rng.nextInt(2));
        return sb.toString();
    }

    // ---------------- init_registers ------------------

    static int[][] initRegisters(String keyBits) {

        int[] R1 = new int[R1_LEN];
        int[] R2 = new int[R2_LEN];
        int[] R3 = new int[R3_LEN];

        // загрузка key_bits
        for (char bit : keyBits.toCharArray()) {
            int b = bit - '0';

            R1[0] ^= b;
            R2[0] ^= b;
            R3[0] ^= b;

            lfsrShift(R1, R1_TAPS);
            lfsrShift(R2, R2_TAPS);
            lfsrShift(R3, R3_TAPS);
        }

        // загрузка FN
        for (char bit : FN.toCharArray()) {
            int b = bit - '0';

            R1[0] ^= b;
            R2[0] ^= b;
            R3[0] ^= b;

            lfsrShift(R1, R1_TAPS);
            lfsrShift(R2, R2_TAPS);
            lfsrShift(R3, R3_TAPS);
        }

        // warm-up 100 циклов
        for (int i = 0; i < 100; i++) {
            int m = majority(R1[R1_SYNC], R2[R2_SYNC], R3[R3_SYNC]);
            if (R1[R1_SYNC] == m) lfsrShift(R1, R1_TAPS);
            if (R2[R2_SYNC] == m) lfsrShift(R2, R2_TAPS);
            if (R3[R3_SYNC] == m) lfsrShift(R3, R3_TAPS);
        }

        return new int[][]{R1, R2, R3};
    }

    // ------------ Flow_encrypt_decrypt ----------------

    static String flow(int[] R1, int[] R2, int[] R3, int nBits) {
        StringBuilder stream = new StringBuilder();

        for (int i = 0; i < nBits; i++) {

            int m = majority(R1[R1_SYNC], R2[R2_SYNC], R3[R3_SYNC]);

            if (R1[R1_SYNC] == m) lfsrShift(R1, R1_TAPS);
            if (R2[R2_SYNC] == m) lfsrShift(R2, R2_TAPS);
            if (R3[R3_SYNC] == m) lfsrShift(R3, R3_TAPS);

            int ksBit = R1[0] ^ R2[0] ^ R3[0];
            stream.append(ksBit);
        }

        return stream.toString();
    }

    static String a5Process(String text, String keyBits) {
        String plaintextBits = textToBits(text);

        int[][] regs = initRegisters(keyBits);
        String ks = flow(regs[0], regs[1], regs[2], plaintextBits.length());

        StringBuilder cipher = new StringBuilder();
        for (int i = 0; i < plaintextBits.length(); i++) {
            cipher.append((plaintextBits.charAt(i) - '0') ^ (ks.charAt(i) - '0'));
        }

        return cipher.toString();
    }

    // ------------------- MAIN MENU --------------------

    public static void main(String[] args) {

        Scanner sc = new Scanner(System.in);

        while (true) {

            System.out.println("\nВыберите действие:");
            System.out.println("1 - Зашифровать");
            System.out.println("2 - Расшифровать");
            System.out.println("3 - Выход");
            System.out.print("Ваш выбор: ");

            String choice = sc.nextLine().trim();

            switch (choice) {
                case "1": {
                    String keyBits = generateKey(256);
                    String keyHex = bitsToHex(keyBits);

                    System.out.println("Сгенерированный ключ (hex): " + keyHex);

                    System.out.print("Введите текст для шифрования: ");
                    String text = sc.nextLine();

                    String cipherBits = a5Process(text, keyBits);
                    System.out.println("Шифртекст (hex): " + bitsToHex(cipherBits));
                    break;
                }

                case "2": {
                    System.out.print("Введите ключ (hex): ");
                    String keyHex = sc.nextLine().trim();

                    System.out.print("Введите шифртекст (hex): ");
                    String cipherHex = sc.nextLine().trim();

                    String keyBits = hexToBits(keyHex);
                    keyBits = String.format("%256s", keyBits).replace(' ', '0');

                    String cipherBits = hexToBits(cipherHex);

                    int[][] regs = initRegisters(keyBits);
                    String ks = flow(regs[0], regs[1], regs[2], cipherBits.length());

                    StringBuilder plainBits = new StringBuilder();
                    for (int i = 0; i < cipherBits.length(); i++) {
                        plainBits.append((cipherBits.charAt(i) - '0') ^ (ks.charAt(i) - '0'));
                    }

                    System.out.println("Расшифрованный текст: " + bitsToText(plainBits.toString()));
                    break;
                }

                case "3":
                    System.out.println("Выход.");
                    return;

                default:
                    System.out.println("Неверный выбор, попробуйте снова.");
            }
        }
    }
}
