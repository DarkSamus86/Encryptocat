package org.darksamus86.SPN;

import static org.darksamus86.encryption_mode.EncryptionMode.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

/**
 * SPN wrapper — использует утилиты из EncryptionMode (статический импорт).
 * В этом файле осталась только логика SPN (encryptBlock/decryptBlock, режимы ECB/CBC, main).
 */
public class SPN {

    // ---------- Шифрование/Дешифрование одного 512-битного блока ----------
    public static String encryptBlock(String plaintextBits, List<String> roundKeys) {
        // разбиваем на 4 блока по 128
        List<String> blocks = splitIntoBlocks(plaintextBits, 128);
        // если блоков меньше 4, дополняем нулями до 4*128
        while (blocks.size() < 4) blocks.add("0".repeat(128));
        List<String> encryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String rk = roundKeys.get(i);
            String xorOut = xorBits(blocks.get(i), rk);
            String sboxOut = sboxSubstitution4bit(xorOut, false);
            // используем pboxPermutation из EncryptionMode:
            String pboxOut = pboxPermutation(sboxOut, false, null, sboxOut.length());
            encryptedBlocks.add(pboxOut);
        }
        return String.join("", encryptedBlocks);
    }

    public static String decryptBlock(String cipherBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(cipherBits, 128);
        while (blocks.size() < 4) blocks.add("0".repeat(128));
        List<String> decryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String pboxInv = pboxPermutation(blocks.get(i), true, null, blocks.get(i).length());
            String sboxInv = sboxSubstitution4bit(pboxInv, true);
            String xorOut = xorBits(sboxInv, roundKeys.get(i));
            decryptedBlocks.add(xorOut);
        }
        return String.join("", decryptedBlocks);
    }

    // ---------- Режимы ECB / CBC для произвольной длины (с блокировкой по 512 бит) ----------
    public static String ecbEncrypt(String plaintextBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(plaintextBits, 512);
        StringBuilder ciphertext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < 512) block = block + "0".repeat(512 - block.length());
            ciphertext.append(encryptBlock(block, roundKeys));
        }
        return ciphertext.toString();
    }

    public static String ecbDecrypt(String cipherBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(cipherBits, 512);
        StringBuilder plaintext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < 512) block = block + "0".repeat(512 - block.length());
            plaintext.append(decryptBlock(block, roundKeys));
        }
        return plaintext.toString();
    }

    public static String cbcEncrypt(String plaintextBits, List<String> roundKeys, String iv) {
        List<String> blocks = splitIntoBlocks(plaintextBits, 512);
        String prev = leftPadTo(iv, 512); // from EncryptionMode (package-private helper is private there)
        // NOTE: leftPadTo in EncryptionMode is private — we cannot call it here.
        // We'll emulate leftPadTo behavior locally to avoid changing EncryptionMode:
        prev = zfill(iv, 512);

        StringBuilder ciphertext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < 512) block = block + "0".repeat(512 - block.length());
            String xored = xorBits(block, prev);
            String encrypted = encryptBlock(xored, roundKeys);
            ciphertext.append(encrypted);
            prev = encrypted;
        }
        return ciphertext.toString();
    }

    public static String cbcDecrypt(String cipherBits, List<String> roundKeys, String iv) {
        List<String> blocks = splitIntoBlocks(cipherBits, 512);
        String prev = zfill(iv, 512);

        StringBuilder plaintext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < 512) block = block + "0".repeat(512 - block.length());
            String decrypted = decryptBlock(block, roundKeys);
            String xored = xorBits(decrypted, prev);
            plaintext.append(xored);
            prev = block;
        }
        return plaintext.toString();
    }

    // Небольшая утилита zfill (аналог leftPadTo), чтобы не менять EncryptionMode приватные методы
    private static String zfill(String s, int len) {
        if (s == null) s = "";
        if (s.length() >= len) return s.substring(0, len);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len - s.length(); i++) sb.append('0');
        sb.append(s);
        return sb.toString();
    }

    // ---------- Main: CLI (использует функции из EncryptionMode) ----------
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.println("\nМеню:");
            System.out.println("1 - Зашифровать");
            System.out.println("2 - Расшифровать");
            System.out.println("3 - Выход");
            System.out.print("Ваш выбор: ");
            String choice = sc.nextLine();

            if (choice.equals("1") || choice.equals("2")) {
                System.out.println("\nВыберите режим:");
                System.out.println("1 - ECB");
                System.out.println("2 - CBC");
                System.out.print("Режим: ");
                String mode = sc.nextLine();

                String key256;
                String keyHex;
                if (choice.equals("1")) { // при шифровании генерируем ключ
                    key256 = generateKey(256);
                    keyHex = bitsToHex(key256);
                    System.out.println("\nСгенерированный 256-битный ключ (HEX):");
                    System.out.println(keyHex);
                } else { // при расшифровке пользователь вводит ключ
                    System.out.print("\nВведите ключ (HEX): ");
                    keyHex = sc.nextLine();
                    try {
                        key256 = hexToBits(keyHex);
                    } catch (Exception e) {
                        System.out.println("Некорректный HEX-ключ.");
                        continue;
                    }
                }

                // В простом SPN-реализации используем 4 round-ключа (K1,K2,K1,K2) как в оригинале
                String K1 = key256.substring(0, 128);
                String K2 = key256.substring(128);
                List<String> roundKeys = List.of(K1, K2, K1, K2);

                if (choice.equals("1")) { // Шифрование
                    System.out.print("\nВведите открытый текст: ");
                    String plaintext = sc.nextLine();
                    String bits = detectAndConvertToBits(plaintext);
                    bits = pkcs7Pad(bits, 512); // pad to 512-blocks

                    String cipherBits;
                    String iv = null;
                    if ("1".equals(mode)) { // ECB
                        cipherBits = ecbEncrypt(bits, roundKeys);
                        System.out.println("\nРежим: ECB");
                    } else { // CBC
                        iv = generateIV(128);
                        String ivHex = bitsToHex(iv);
                        System.out.println("\nРежим: CBC");
                        System.out.println("IV (HEX): " + ivHex);
                        cipherBits = cbcEncrypt(bits, roundKeys, iv);
                    }

                    String cipherHex = bitsToHex(cipherBits);
                    System.out.println("\nКлюч (HEX): " + keyHex);
                    System.out.println("\nЗашифрованный текст (HEX):");
                    System.out.println(cipherHex);

                } else { // Расшифровка
                    System.out.print("Введите зашифрованный текст (HEX): ");
                    String cipherHex = sc.nextLine();
                    String cipherBits;
                    try {
                        cipherBits = hexToBits(cipherHex);
                    } catch (Exception e) {
                        System.out.println("Некорректный HEX-текст.");
                        continue;
                    }

                    String decryptedBits;
                    if ("1".equals(mode)) { // ECB
                        decryptedBits = ecbDecrypt(cipherBits, roundKeys);
                        System.out.println("\nРежим: ECB");
                    } else { // CBC
                        System.out.print("Введите IV (HEX): ");
                        String ivHex = sc.nextLine();
                        String ivBits;
                        try {
                            ivBits = hexToBits(ivHex);
                        } catch (Exception e) {
                            System.out.println("Некорректный HEX-IV.");
                            continue;
                        }
                        decryptedBits = cbcDecrypt(cipherBits, roundKeys, ivBits);
                        System.out.println("\nРежим: CBC");
                    }

                    String unpaddedBits = pkcs7Unpad(decryptedBits);
                    String decryptedText = bitsToText(unpaddedBits);
                    System.out.println("\nРасшифрованный текст:");
                    System.out.println(decryptedText.replace("\0", "").trim());
                }

            } else if (choice.equals("3")) {
                System.out.println("Выход.");
                break;
            } else {
                System.out.println("Неверный выбор.");
            }
        }
    }
}