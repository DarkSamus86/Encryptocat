package org.darksamus86.SPN;

import java.util.*;
import java.util.stream.Collectors;

public class SPN {

    // ---------- Генерация ключей + IV ----------
    public static String generateKey(int bits) {
        Random random = new Random();
        StringBuilder key = new StringBuilder(bits);
        for (int i = 0; i < bits; i++) {
            key.append(random.nextBoolean() ? '1' : '0');
        }
        return key.toString();
    }

    public static String generateIV(int bits) {
        Random random = new Random();
        StringBuilder iv = new StringBuilder(bits);
        for (int i = 0; i < bits; i++) {
            iv.append(random.nextBoolean() ? '1' : '0');
        }
        return iv.toString();
    }

    // ---------- Конвертации ----------
    public static String bitsToHex(String bits) {
        // BigInteger constructor with sign-magnitude requires a "1" prefix for positive long bitstrings starting with zero
        java.math.BigInteger bi = new java.math.BigInteger(bits, 2);
        String hex = bi.toString(16).toUpperCase();
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
            String nibble = bits.substring(i, i + 4);
            int val = Integer.parseInt(nibble, 2);
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
                } else {
                    permuted[dest - 1] = '0';
                }
            }
            out.append(new String(permuted));
        }
        return out.toString();
    }

    // ---------- XOR ----------
    public static String xorBits(String a, String b) {
        StringBuilder sb = new StringBuilder();
        int len = Math.min(a.length(), b.length());
        for (int i = 0; i < len; i++) {
            sb.append(a.charAt(i) == b.charAt(i) ? '0' : '1');
        }
        // if lengths differ, append remaining bits of longer operand (xor with implicit 0)
        if (a.length() > len) sb.append(a.substring(len));
        if (b.length() > len) sb.append(b.substring(len));
        return sb.toString();
    }

    // ---------- Блокирование ----------
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

    // ---------- Шифрование/Дешифрование одного 512-битного блока ----------
    public static String encryptBlock(String plaintextBits, List<String> roundKeys) {
        // разбиваем на 4 блока по 128
        List<String> blocks = splitIntoBlocks(plaintextBits, 128);
        // если блоков меньше 4, дополняем нулями до 4*128
        while (blocks.size() < 4) blocks.add("0".repeat(128));
        List<String> encryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String xorOut = xorBits(blocks.get(i), roundKeys.get(i));
            String sboxOut = sboxSubstitution4bit(xorOut, false);
            String pboxOut = pboxPermutation(sboxOut, false);
            encryptedBlocks.add(pboxOut);
        }
        return String.join("", encryptedBlocks);
    }

    public static String decryptBlock(String cipherBits, List<String> roundKeys) {
        List<String> blocks = splitIntoBlocks(cipherBits, 128);
        while (blocks.size() < 4) blocks.add("0".repeat(128));
        List<String> decryptedBlocks = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            String pboxInv = pboxPermutation(blocks.get(i), true);
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
            // если блок короче 512, дополняем нулями (обычно уже есть PKCS7)
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
        String prev = leftPadTo(iv, 512); // zfill behavior
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
        String prev = leftPadTo(iv, 512);
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

    // zfill аналог — дополняет слева нулями до нужной длины
    private static String leftPadTo(String s, int len) {
        if (s.length() >= len) return s;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len - s.length(); i++) sb.append('0');
        sb.append(s);
        return sb.toString();
    }

    // ---------- Утилита для инверсии мап ----------
    public static <K, V> Map<V, K> invertMap(Map<K, V> map) {
        Map<V, K> inverted = new HashMap<>();
        for (Map.Entry<K, V> e : map.entrySet()) {
            inverted.put(e.getValue(), e.getKey());
        }
        return inverted;
    }

    // ---------- Основное меню (с ECB/CBC + IV) ----------
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

                // ключ
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
