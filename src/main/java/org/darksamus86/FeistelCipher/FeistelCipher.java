package org.darksamus86.FeistelCipher;

import org.darksamus86.encryption_mode.EncryptionMode;
import java.util.List;
import java.util.Map;

import java.util.Scanner;

public class FeistelCipher {

    private static final int NUM_ROUNDS = 16;
    private static final int BLOCK_SIZE = 512; // размер блока в битах
    private static final int ROUND_KEY_SIZE = 256; // размер ключа раунда

    // --- Шифрование блока Feistel ---
    public static String encryptBlock(String blockBits, String keyBits) {
        List<String> roundKeys = EncryptionMode.generateRoundKeys(keyBits, NUM_ROUNDS, ROUND_KEY_SIZE);
        return EncryptionMode.feistelEncryptBlock(blockBits, roundKeys);
    }

    // --- Расшифровка блока Feistel ---
    public static String decryptBlock(String blockBits, String keyBits) {
        List<String> roundKeys = EncryptionMode.generateRoundKeys(keyBits, NUM_ROUNDS, ROUND_KEY_SIZE);
        return EncryptionMode.feistelDecryptBlock(blockBits, roundKeys);
    }

    // --- Шифрование текста ---
    public static String encrypt(String plaintext, String key) {
        String bits = EncryptionMode.textToBits(plaintext);
        String keyBits = EncryptionMode.textToBits(key);
        List<String> blocks = EncryptionMode.splitIntoBlocks(bits, BLOCK_SIZE);

        StringBuilder cipherBits = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < BLOCK_SIZE) {
                while (block.length() < BLOCK_SIZE) block += "0";
            }
            cipherBits.append(encryptBlock(block, keyBits));
        }
        return EncryptionMode.bitsToHex(cipherBits.toString());
    }

    // --- Расшифровка текста ---
    public static String decrypt(String cipherHex, String key) {
        String cipherBits = EncryptionMode.hexToBits(cipherHex);
        String keyBits = EncryptionMode.textToBits(key);
        List<String> blocks = EncryptionMode.splitIntoBlocks(cipherBits, BLOCK_SIZE);

        StringBuilder plainBits = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < BLOCK_SIZE) {
                while (block.length() < BLOCK_SIZE) block += "0";
            }
            plainBits.append(decryptBlock(block, keyBits));
        }
        return EncryptionMode.bitsToText(plainBits.toString());
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {

            System.out.println("\nМеню (Feistel):");
            System.out.println("1 — Зашифровать");
            System.out.println("2 — Расшифровать");
            System.out.println("3 — Выход");
            System.out.print("Ваш выбор: ");

            String choice = scanner.nextLine().trim();

            // ---------- ENCRYPT ----------
            if (choice.equals("1")) {

                // Генерация ключа (HEX)
                String keyBits = EncryptionMode.generateKey(ROUND_KEY_SIZE);
                String keyHex = EncryptionMode.bitsToHex(keyBits);

                System.out.println("\nСгенерированный ключ (HEX):");
                System.out.println(keyHex);

                System.out.print("\nВведите открытый текст: ");
                String text = scanner.nextLine();

                String cipherHex = encrypt(text, keyHex);

                System.out.println("\nЗашифрованный текст (HEX):");
                System.out.println(cipherHex);

            }
            // ---------- DECRYPT ----------
            else if (choice.equals("2")) {

                System.out.print("Введите ключ (HEX): ");
                String keyHex = scanner.nextLine().trim();

                System.out.print("Введите шифртекст (HEX): ");
                String cipherHex = scanner.nextLine().trim();

                String plaintext = decrypt(cipherHex, keyHex);

                System.out.println("\nРасшифрованный текст:");
                System.out.println(plaintext);

            }
            // ---------- EXIT ----------
            else if (choice.equals("3")) {
                System.out.println("Выход.");
                break;
            }
            else {
                System.out.println("Неверный выбор.");
            }
        }

        scanner.close();
    }
}
