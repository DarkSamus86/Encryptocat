package org.darksamus86.encryption_mode;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class EncryptionMode {
    private static final SecureRandom RANDOM = new SecureRandom();

    // S-box
    public static final Map<Integer, Integer> SBOX_HEX = new LinkedHashMap<>();
    public static final Map<Integer, Integer> INV_SBOX_HEX = new LinkedHashMap<>();
    static {
        SBOX_HEX.put(0x0, 0x8); SBOX_HEX.put(0x1, 0x3); SBOX_HEX.put(0x2, 0x7); SBOX_HEX.put(0x3, 0x0);
        SBOX_HEX.put(0x4, 0x1); SBOX_HEX.put(0x5, 0xA); SBOX_HEX.put(0x6, 0x5); SBOX_HEX.put(0x7, 0xF);
        SBOX_HEX.put(0x8, 0x2); SBOX_HEX.put(0x9, 0x4); SBOX_HEX.put(0xA, 0xD); SBOX_HEX.put(0xB, 0x6);
        SBOX_HEX.put(0xC, 0x9); SBOX_HEX.put(0xD, 0xB); SBOX_HEX.put(0xE, 0xC); SBOX_HEX.put(0xF, 0xE);
        for (Map.Entry<Integer,Integer> e : SBOX_HEX.entrySet()) {
            INV_SBOX_HEX.put(e.getValue(), e.getKey());
        }
    }

    // default pbox map for 16 bits (1-based indices)
    public static final Map<Integer, Integer> DEFAULT_PBOX_MAP_16 = new LinkedHashMap<>();
    static {
        DEFAULT_PBOX_MAP_16.put(1, 12); DEFAULT_PBOX_MAP_16.put(2, 3); DEFAULT_PBOX_MAP_16.put(3, 9); DEFAULT_PBOX_MAP_16.put(4, 14);
        DEFAULT_PBOX_MAP_16.put(5, 1); DEFAULT_PBOX_MAP_16.put(6, 7); DEFAULT_PBOX_MAP_16.put(7, 15); DEFAULT_PBOX_MAP_16.put(8, 4);
        DEFAULT_PBOX_MAP_16.put(9, 10); DEFAULT_PBOX_MAP_16.put(10, 16); DEFAULT_PBOX_MAP_16.put(11, 8); DEFAULT_PBOX_MAP_16.put(12, 2);
        DEFAULT_PBOX_MAP_16.put(13, 13); DEFAULT_PBOX_MAP_16.put(14, 6); DEFAULT_PBOX_MAP_16.put(15, 11); DEFAULT_PBOX_MAP_16.put(16, 5);
    }

    // --- Random key/iv generation (bits as String of '0'/'1') ---
    public static String generateKey(int bits) {
        StringBuilder sb = new StringBuilder(bits);
        for (int i = 0; i < bits; i++) {
            sb.append(RANDOM.nextBoolean() ? '1' : '0');
        }
        return sb.toString();
    }

    public static String generateIV(int bits) {
        return generateKey(bits);
    }

    // --- Conversions ---
    public static String bitsToHex(String bits) {
        if (bits.length() == 0) return "";
        BigInteger bi = new BigInteger(bits, 2);
        int hexLen = (bits.length() + 3) / 4;
        String hex = bi.toString(16).toUpperCase();
        // pad
        if (hex.length() < hexLen) {
            StringBuilder z = new StringBuilder();
            for (int i = 0; i < hexLen - hex.length(); i++) z.append('0');
            hex = z + hex;
        }
        return hex;
    }

    public static String hexToBits(String hexStr) {
        if (hexStr.length() == 0) return "";
        BigInteger bi = new BigInteger(hexStr, 16);
        int bitsLen = hexStr.length() * 4;
        String bits = bi.toString(2);
        if (bits.length() < bitsLen) {
            StringBuilder z = new StringBuilder();
            for (int i = 0; i < bitsLen - bits.length(); i++) z.append('0');
            bits = z + bits;
        }
        return bits;
    }

    public static String bitsToText(String bits) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i + 8 <= bits.length(); i += 8) {
            String byteStr = bits.substring(i, i + 8);
            int val = Integer.parseInt(byteStr, 2);
            sb.append((char) val);
        }
        return sb.toString();
    }

    public static String textToBits(String text) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            String b = Integer.toBinaryString((int) c);
            // pad to 8
            if (b.length() < 8) {
                StringBuilder z = new StringBuilder();
                for (int i = 0; i < 8 - b.length(); i++) z.append('0');
                b = z + b;
            }
            sb.append(b);
        }
        return sb.toString();
    }

    public static String detectAndConvertToBits(String userInput) {
        if (userInput.matches("[01]+")) {
            return userInput;
        }
        if (userInput.matches("[0-9A-Fa-f]+")) {
            return hexToBits(userInput);
        }
        return textToBits(userInput);
    }

    // --- S-box substitution for 4-bit nibbles ---
    public static String sboxSubstitution4bit(String bits, boolean inverse) {
        StringBuilder out = new StringBuilder();
        Map<Integer,Integer> table = inverse ? INV_SBOX_HEX : SBOX_HEX;
        for (int i = 0; i < bits.length(); i += 4) {
            String nibble;
            if (i + 4 <= bits.length()) nibble = bits.substring(i, i + 4);
            else {
                nibble = bits.substring(i);
                // right-pad with zeros
                while (nibble.length() < 4) nibble += '0';
            }
            int val = Integer.parseInt(nibble, 2);
            int sub = table.getOrDefault(val, 0);
            String s = Integer.toBinaryString(sub);
            if (s.length() < 4) {
                StringBuilder z = new StringBuilder();
                for (int k = 0; k < 4 - s.length(); k++) z.append('0');
                s = z + s;
            }
            out.append(s);
        }
        return out.toString();
    }

    // --- P-box helpers ---
    public static Map<Integer, Integer> makeIdentityPboxMap(int nBits) {
        Map<Integer, Integer> m = new LinkedHashMap<>();
        for (int i = 1; i <= nBits; i++) m.put(i, i);
        return m;
    }

    /**
     * pbox_map: map from source position (1-based) -> dest position (1-based)
     * chunk_size: number of bits per block to permute
     * inverse: if true, apply inverse permutation
     */
    public static String pboxPermutation(String bits, boolean inverse, Map<Integer,Integer> pboxMap, int chunkSize) {
        Map<Integer,Integer> table;
        if (pboxMap == null) {
            if (chunkSize == 16) {
                table = new LinkedHashMap<>(DEFAULT_PBOX_MAP_16);
            } else {
                table = makeIdentityPboxMap(chunkSize);
            }
        } else {
            if (inverse) {
                // invert map
                table = new LinkedHashMap<>();
                for (Map.Entry<Integer,Integer> e : pboxMap.entrySet()) table.put(e.getValue(), e.getKey());
            } else {
                table = new LinkedHashMap<>(pboxMap);
            }
        }

        StringBuilder out = new StringBuilder();
        for (int i = 0; i < bits.length(); i += chunkSize) {
            String block;
            if (i + chunkSize <= bits.length()) block = bits.substring(i, i + chunkSize);
            else {
                block = bits.substring(i);
                while (block.length() < chunkSize) block += '0';
            }
            char[] permuted = new char[chunkSize];
            for (int p = 0; p < chunkSize; p++) permuted[p] = '0';
            for (Map.Entry<Integer,Integer> e : table.entrySet()) {
                int src = e.getKey();
                int dest = e.getValue();
                if (src >= 1 && src <= block.length() && dest >= 1 && dest <= chunkSize) {
                    permuted[dest - 1] = block.charAt(src - 1);
                }
            }
            out.append(new String(permuted));
        }
        return out.toString();
    }

    // --- XOR ---
    public static String xorBits(String bits1, String bits2) {
        int len = Math.min(bits1.length(), bits2.length());
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            char a = bits1.charAt(i), b = bits2.charAt(i);
            sb.append(a == b ? '0' : '1');
        }
        return sb.toString();
    }

    // --- Split into blocks ---
    public static List<String> splitIntoBlocks(String binText, int blockSize) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < binText.length(); i += blockSize) {
            int end = Math.min(binText.length(), i + blockSize);
            out.add(binText.substring(i, end));
        }
        return out;
    }

    // --- PKCS7 pad/unpad (operates on bits, block_size_bits must be multiple of 8) ---
    public static String pkcs7Pad(String bits, int blockSizeBits) {
        if (blockSizeBits % 8 != 0) throw new IllegalArgumentException("block_size_bits must be multiple of 8");
        int byteLen = bits.length() / 8;
        int blockSizeBytes = blockSizeBits / 8;
        int paddingLen = blockSizeBytes - (byteLen % blockSizeBytes);
        if (paddingLen == 0) paddingLen = blockSizeBytes;
        String paddingByte = Integer.toBinaryString(paddingLen);
        while (paddingByte.length() < 8) paddingByte = "0" + paddingByte;
        StringBuilder padded = new StringBuilder(bits);
        for (int i = 0; i < paddingLen; i++) padded.append(paddingByte);
        return padded.toString();
    }

    public static String pkcs7Unpad(String bits) {
        if (bits.length() % 8 != 0) return bits;
        String lastByte = bits.substring(bits.length() - 8);
        int padVal = Integer.parseInt(lastByte, 2);
        if (padVal <= 0 || padVal > (bits.length() / 8)) return bits;
        return bits.substring(0, bits.length() - (padVal * 8));
    }

    // --- Round key generator (LCG) ---
    public static List<String> generateRoundKeys(String keyBits, int numRounds, int roundKeySize) {
        if (keyBits.length() < 2) throw new IllegalArgumentException("key_bits too short");
        int half = keyBits.length() / 2;
        String K1 = keyBits.substring(0, half);
        String K2 = keyBits.substring(half);
        BigInteger bi1 = new BigInteger(K1, 2);
        BigInteger bi2 = new BigInteger(K2, 2);
        BigInteger xor = bi1.xor(bi2);
        long seed = xor.longValue() & 0xFFFFFFFFL;

        long a = 1664525L;
        long c = 1013904223L;
        long m = (1L << 32);

        List<String> roundKeys = new ArrayList<>();
        for (int i = 0; i < numRounds; i++) {
            seed = (a * ((seed + i) & 0xFFFFFFFFL) + c) % m;
            long localSeed = seed;
            StringBuilder keyBitsN = new StringBuilder();
            int words = (roundKeySize + 31) / 32;
            for (int w = 0; w < words; w++) {
                localSeed = (a * localSeed + c) % m;
                String wbits = Long.toBinaryString(localSeed & 0xFFFFFFFFL);
                while (wbits.length() < 32) wbits = "0" + wbits;
                keyBitsN.append(wbits);
            }
            String kk = keyBitsN.toString();
            if (kk.length() > roundKeySize) kk = kk.substring(0, roundKeySize);
            roundKeys.add(kk);
        }
        return roundKeys;
    }

    // --- Function F (uses xor, sbox, pbox) ---
    public static String fFunction(String rightHalf, String roundKey) {
        String mixed = xorBits(rightHalf, roundKey);
        String substituted = sboxSubstitution4bit(mixed, false);
        String permuted = pboxPermutation(substituted, false, null, substituted.length());
        return permuted;
    }

    // --- Feistel round and inverse ---
    public static Pair<String,String> feistelRound(String L, String R, String roundKey) {
        String newL = R;
        String fOut = fFunction(R, roundKey);
        String newR = xorBits(L, fOut);
        return new Pair<>(newL, newR);
    }

    public static Pair<String,String> feistelRoundUnapply(String Lcur, String Rcur, String roundKey) {
        String prevR = Lcur;
        String fOut = fFunction(prevR, roundKey);
        String prevL = xorBits(Rcur, fOut);
        return new Pair<>(prevL, prevR);
    }

    // --- Feistel encrypt/decrypt blocks (512-bit block, halves 256/256) ---
    public static String feistelEncryptBlock(String blockBits, List<String> roundKeys) {
        String L = blockBits.substring(0, Math.min(256, blockBits.length()));
        String R = blockBits.length() >= 256 ? blockBits.substring(256, Math.min(512, blockBits.length())) : "";
        for (String k : roundKeys) {
            Pair<String,String> p = feistelRound(L, R, k);
            L = p.first;
            R = p.second;
        }
        return L + R;
    }

    public static String feistelDecryptBlock(String blockBits, List<String> roundKeys) {
        String L = blockBits.substring(0, Math.min(256, blockBits.length()));
        String R = blockBits.length() >= 256 ? blockBits.substring(256, Math.min(512, blockBits.length())) : "";
        for (int i = roundKeys.size() - 1; i >= 0; i--) {
            Pair<String,String> p = feistelRoundUnapply(L, R, roundKeys.get(i));
            L = p.first;
            R = p.second;
        }
        return L + R;
    }

    // --- SPN encrypt/decrypt for a block (processes in round_key_size-chunks) ---
    public static String spnEncryptBlock(String plaintextBits, List<String> roundKeys, int roundKeySize, Map<Integer,Integer> pboxMap) {
        int chunk = roundKeySize;
        List<String> blocks = splitIntoBlocks(plaintextBits, chunk);
        for (String roundKey : roundKeys) {
            List<String> newBlocks = new ArrayList<>();
            for (String block : blocks) {
                if (block.length() < chunk) {
                    while (block.length() < chunk) block += '0';
                }
                String xorOut = xorBits(block, roundKey.substring(0, Math.min(roundKey.length(), block.length())));
                String sboxOut = sboxSubstitution4bit(xorOut, false);
                String pboxOut = pboxPermutation(sboxOut, false, pboxMap, block.length());
                newBlocks.add(pboxOut);
            }
            blocks = newBlocks;
        }
        StringBuilder sb = new StringBuilder();
        for (String b : blocks) sb.append(b);
        return sb.toString();
    }

    public static String spnDecryptBlock(String cipherBits, List<String> roundKeys, int roundKeySize, Map<Integer,Integer> pboxMap) {
        int chunk = roundKeySize;
        List<String> blocks = splitIntoBlocks(cipherBits, chunk);
        for (int r = roundKeys.size() - 1; r >= 0; r--) {
            String roundKey = roundKeys.get(r);
            List<String> newBlocks = new ArrayList<>();
            for (String block : blocks) {
                if (block.length() < chunk) {
                    while (block.length() < chunk) block += '0';
                }
                String pboxInv = pboxPermutation(block, true, pboxMap, block.length());
                String sboxInv = sboxSubstitution4bit(pboxInv, true);
                String xorOut = xorBits(sboxInv, roundKey.substring(0, Math.min(roundKey.length(), sboxInv.length())));
                newBlocks.add(xorOut);
            }
            blocks = newBlocks;
        }
        StringBuilder sb = new StringBuilder();
        for (String b : blocks) sb.append(b);
        return sb.toString();
    }

    // --- ECB ---
    public static String ecbEncrypt(String plaintextBits, List<String> roundKeys, int blockSizeBits, int roundKeySize, Map<Integer,Integer> pboxMap) {
        List<String> blocks = splitIntoBlocks(plaintextBits, blockSizeBits);
        StringBuilder ciphertext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < blockSizeBits) {
                while (block.length() < blockSizeBits) block += '0';
            }
            ciphertext.append(spnEncryptBlock(block, roundKeys, roundKeySize, pboxMap));
        }
        return ciphertext.toString();
    }

    public static String ecbDecrypt(String cipherBits, List<String> roundKeys, int blockSizeBits, int roundKeySize, Map<Integer,Integer> pboxMap) {
        List<String> blocks = splitIntoBlocks(cipherBits, blockSizeBits);
        StringBuilder plaintext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < blockSizeBits) {
                while (block.length() < blockSizeBits) block += '0';
            }
            plaintext.append(spnDecryptBlock(block, roundKeys, roundKeySize, pboxMap));
        }
        return plaintext.toString();
    }

    // --- CBC ---
    public static String cbcEncrypt(String plaintextBits, List<String> roundKeys, String iv, int blockSizeBits, int roundKeySize, Map<Integer,Integer> pboxMap) {
        List<String> blocks = splitIntoBlocks(plaintextBits, blockSizeBits);
        String prev = leftPadTo(iv, blockSizeBits);
        StringBuilder ciphertext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < blockSizeBits) {
                while (block.length() < blockSizeBits) block += '0';
            }
            String xored = xorBits(block, prev);
            String encrypted = spnEncryptBlock(xored, roundKeys, roundKeySize, pboxMap);
            ciphertext.append(encrypted);
            prev = encrypted;
        }
        return ciphertext.toString();
    }

    public static String cbcDecrypt(String cipherBits, List<String> roundKeys, String iv, int blockSizeBits, int roundKeySize, Map<Integer,Integer> pboxMap) {
        List<String> blocks = splitIntoBlocks(cipherBits, blockSizeBits);
        String prev = leftPadTo(iv, blockSizeBits);
        StringBuilder plaintext = new StringBuilder();
        for (String block : blocks) {
            if (block.length() < blockSizeBits) {
                while (block.length() < blockSizeBits) block += '0';
            }
            String decrypted = spnDecryptBlock(block, roundKeys, roundKeySize, pboxMap);
            String xored = xorBits(decrypted, prev);
            plaintext.append(xored);
            prev = block;
        }
        return plaintext.toString();
    }

    // helper: pad or zfill to desired bit length on the left
    public static String leftPadTo(String s, int len) {
        if (s == null) s = "";
        if (s.length() >= len) return s.substring(0, len);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len - s.length(); i++) sb.append('0');
        sb.append(s);
        return sb.toString();
    }

    // --- Simple Pair utility ---
    public static class Pair<A,B> {
        public A first;
        public B second;
        public Pair(A a, B b) { first = a; second = b; }
    }

    // --- Example main for quick smoke test (optional) ---
    public static void main(String[] args) {
        String key = generateKey(256);
        System.out.println("Key bits len: " + key.length());
        String iv = generateIV(128);
        System.out.println("IV bits len: " + iv.length());
        String text = "Hello";
        String bits = textToBits(text);
        System.out.println("Text bits: " + bits);
        String padded = pkcs7Pad(bits, 512);
        System.out.println("Padded len: " + padded.length());
        List<String> roundKeys = generateRoundKeys(key, 10, 128);
        String cipher = ecbEncrypt(padded, roundKeys, 512, 128, null);
        System.out.println("Cipher len: " + cipher.length());
        String plain = ecbDecrypt(cipher, roundKeys, 512, 128, null);
        System.out.println("Recovered len: " + plain.length());
        System.out.println("Unpadded text: " + bitsToText(pkcs7Unpad(plain)));
    }
}

