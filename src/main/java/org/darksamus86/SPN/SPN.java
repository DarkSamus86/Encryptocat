package org.darksamus86.SPN;

import java.util.*;
import java.util.stream.Collectors;

public class SPN {

    // ---------- Генерация ключей ----------
    public static String generateKey(int bits) {
        Random random = new Random();
        StringBuilder key = new StringBuilder(bits);
        for (int i = 0; i < bits; i++) {
            key.append(random.nextBoolean() ? '1' : '0');
        }
        return key.toString();
    }

    // ---------- Конвертации ----------
    public static String bitsToHex(String bits) {
        String hex = new java.math.BigInteger(bits, 2).toString(16).toUpperCase();
        while (hex.length() < bits.length() / 4) hex = "0" + hex;
        return hex;
    }

    public static String hexToBits(String hexStr) {
        String bits = new java.math.BigInteger(hexStr, 16).toString(2);
        while (bits.length() < hexStr.length() * 4) bits = "0" + bits;
        return bits;
    }

    public static String bitsToText(String bits) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 8 <= bits.length(); i += 8) {
            int val = Integer.parseInt(bits.substring(i, i + 8), 2);
            sb.append((char) val);
        }
        return sb.toString();
    }

    public static String detectAndConvertToBits(String input) {
        if (input.matches("[01]+")) return input;
        if (input.matches("[0-9A-Fa-f]+")) return hexToBits(input);
        return input.chars()
                .mapToObj(c -> String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'))
                .collect(Collectors.joining());
    }

    // ---------- S-box ----------
    static final Map<Integer, Integer> SBOX_HEX = Map.ofEntries(
            Map.entry(0x0, 0x8), Map.entry(0x1, 0x3), Map.entry(0x2, 0x7), Map.entry(0x3, 0x0),
            Map.entry(0x4, 0x1), Map.entry(0x5, 0xA), Map.entry(0x6, 0x5), Map.entry(0x7, 0xF),
            Map.entry(0x8, 0x2), Map.entry(0x9, 0x4), Map.entry(0xA, 0xD), Map.entry(0xB, 0x6),
            Map.entry(0xC, 0x9), Map.entry(0xD, 0xB), Map.entry(0xE, 0xC), Map.entry(0xF, 0xE)
    );

    static final Map<Integer, Integer> INV_SBOX_HEX = invertMap(SBOX_HEX);

    public static String sboxSubstitution4bit(String bits, boolean inverse) {
        Map<Integer, Integer> table = inverse ? INV_SBOX_HEX : SBOX_HEX;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i + 4 <= bits.length(); i += 4) {
            int val = Integer.parseInt(bits.substring(i, i + 4), 2);
            int subVal = table.get(val);
            out.append(String.format("%4s", Integer.toBinaryString(subVal)).replace(' ', '0'));
        }
        return out.toString();
    }

    // ---------- P-box ----------
    static final Map<Integer, Integer> PBOX_MAP = Map.ofEntries(
            Map.entry(1, 12), Map.entry(2, 3), Map.entry(3, 9), Map.entry(4, 14),
            Map.entry(5, 1), Map.entry(6, 7), Map.entry(7, 15), Map.entry(8, 4),
            Map.entry(9, 10), Map.entry(10, 16), Map.entry(11, 8), Map.entry(12, 2),
            Map.entry(13, 13), Map.entry(14, 6), Map.entry(15, 11), Map.entry(16, 5)
    );

    static final Map<Integer, Integer> INV_PBOX_MAP = invertMap(PBOX_MAP);

    public static String pboxPermutation(String bits, boolean inverse) {
        Map<Integer, Integer> table = inverse ? INV_PBOX_MAP : PBOX_MAP;
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < bits.length(); i += 16) {
            String block = bits.substring(i, Math.min(i + 16, bits.length()));
            while (block.length() < 16) block = block + "0";
            char[] permuted = new char[16];
            for (Map.Entry<Integer, Integer> e : table.entrySet()) {
                int src = e.getKey(), dest = e.getValue();
                if (src <= block.length()) {
                    permuted[dest - 1] = block.charAt(src - 1);
                }
            }
            out.append(new String(permuted));
        }
        return out.toString();
    }

    // ---------- XOR ----------
    public static String xorBits(String a, String b) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(a.length(), b.length()); i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        return sb.toString();
    }

    public static List<String> splitIntoBlocks(String text, int blockSize) {
        List<String> blocks = new ArrayList<>();
        for (int i = 0; i < text.length(); i += blockSize)
            blocks.add(text.substring(i, Math.min(i + blockSize, text.length())));
        return blocks;
    }

    // ---------- PKCS7 ----------
    public static String pkcs7Pad(String bits, int blockSizeBits) {
        int byteLen = bits.length() / 8;
        int blockSizeBytes = blockSizeBits / 8;
        int paddingLen = blockSizeBytes - (byteLen % blockSizeBytes);
        if (paddingLen == 0) paddingLen = blockSizeBytes;
        String paddingByte = String.format("%8s", Integer.toBinaryString(paddingLen)).replace(' ', '0');
        return bits + paddingByte.repeat(paddingLen);
    }

    public static String pkcs7Unpad(String bits) {
        if (bits.length() % 8 != 0) return bits;
        String lastByte = bits.substring(bits.length() - 8);
        int padVal = Integer.parseInt(lastByte, 2);
        if (padVal <= 0 || padVal > (bits.length() / 8)) return bits;
        return bits.substring(0, bits.length() - padVal * 8);
    }

    // ---------- Шифрование ----------
    public static String encrypt(String plaintextBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(plaintextBits, 128);
        List<String> encryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String xorOut = xorBits(blocks.get(i), roundKeys.get(i));
            String sboxOut = sboxSubstitution4bit(xorOut, false);
            String pboxOut = pboxPermutation(sboxOut, false);
            encryptedBlocks.add(pboxOut);
        }
        return String.join("", encryptedBlocks);
    }

    // ---------- Расшифрование ----------
    public static String decrypt(String cipherBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(cipherBits, 128);
        List<String> decryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String pboxInv = pboxPermutation(blocks.get(i), true);
            String sboxInv = sboxSubstitution4bit(pboxInv, true);
            String xorOut = xorBits(sboxInv, roundKeys.get(i));
            decryptedBlocks.add(xorOut);
        }
        return String.join("", decryptedBlocks);
    }

    // ---------- Утилита для инверсии мап ----------
    public static <K, V> Map<V, K> invertMap(Map<K, V> map) {
        Map<V, K> inverted = new HashMap<>();
        for (Map.Entry<K, V> e : map.entrySet()) {
            inverted.put(e.getValue(), e.getKey());
        }
        return inverted;
    }

    // ---------- Основное меню ----------
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        while (true) {
            System.out.println("\nМеню:");
            System.out.println("1 - Зашифровать");
            System.out.println("2 - Расшифровать");
            System.out.println("3 - Выход");
            System.out.print("Ваш выбор: ");
            String choice = sc.nextLine();

            if (choice.equals("1")) {
                String key256 = generateKey(256);
                String keyHex = bitsToHex(key256);
                System.out.println("\nСгенерированный 256-битный ключ (HEX):");
                System.out.println(keyHex);

                String K1 = key256.substring(0, 128);
                String K2 = key256.substring(128);
                List<String> roundKeys = List.of(K1, K2, K1, K2);

                System.out.print("\nВведите открытый текст: ");
                String plaintext = sc.nextLine();
                String bits = detectAndConvertToBits(plaintext);
                bits = pkcs7Pad(bits, 512);

                String cipherBits = encrypt(bits.substring(0, 512), roundKeys);
                String cipherHex = bitsToHex(cipherBits);

                System.out.println("\nЗашифрованный текст (HEX):");
                System.out.println(cipherHex);

            } else if (choice.equals("2")) {
                System.out.print("\nВведите 256-битный ключ (HEX): ");
                String keyHex = sc.nextLine();
                String keyBits;
                try {
                    keyBits = hexToBits(keyHex);
                } catch (Exception e) {
                    System.out.println("Некорректный HEX-ключ.");
                    continue;
                }

                System.out.print("Введите зашифрованный текст (HEX): ");
                String cipherHex = sc.nextLine();
                String cipherBits;
                try {
                    cipherBits = hexToBits(cipherHex);
                } catch (Exception e) {
                    System.out.println("Некорректный HEX-текст.");
                    continue;
                }

                String K1 = keyBits.substring(0, 128);
                String K2 = keyBits.substring(128);
                List<String> roundKeys = List.of(K1, K2, K1, K2);

                String decryptedBits = decrypt(cipherBits, roundKeys);
                String unpaddedBits = pkcs7Unpad(decryptedBits);
                String decryptedText = bitsToText(unpaddedBits);

                System.out.println("\nРасшифрованный текст:");
                System.out.println(decryptedText.replace("\0", "").trim());

            } else if (choice.equals("3")) {
                System.out.println("Выход.");
                break;
            } else {
                System.out.println("Неверный выбор.");
            }
        }
    }
}
