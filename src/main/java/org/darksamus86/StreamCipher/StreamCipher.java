package org.darksamus86.StreamCipher;

import java.util.*;

public class StreamCipher {

    public static String detectKeyFormat(String keyStr) {
        keyStr = keyStr.trim();
        if (keyStr.matches("[01]+")) {
            return "binary";
        } else if (keyStr.matches("\\d+")) {
            return "decimal";
        } else if (keyStr.startsWith("0x") || keyStr.matches("[0-9a-fA-F]+")) {
            return "hex";
        } else {
            return "text";
        }
    }

    public static String toBinary(String keyStr) {
        String fmt = detectKeyFormat(keyStr);
        switch (fmt) {
            case "binary":
                return keyStr;
            case "decimal":
                return Integer.toBinaryString(Integer.parseInt(keyStr));
            case "hex":
                return new java.math.BigInteger(
                        keyStr.startsWith("0x") ? keyStr.substring(2) : keyStr, 16
                ).toString(2);
            default: // text
                StringBuilder bin = new StringBuilder();
                for (char ch : keyStr.toCharArray()) {
                    bin.append(String.format("%8s", Integer.toBinaryString(ch))
                            .replace(' ', '0'));
                }
                return bin.toString();
        }
    }

    public static List<Integer> generateTaps(int length, int numTaps) {
        List<Integer> positions = new ArrayList<>();
        for (int i = 0; i < length; i++) {
            positions.add(i);
        }
        Collections.shuffle(positions);
        return positions.subList(0, Math.min(numTaps, length));
    }

    public static String streamEncrypt(String plaintext, String key, List<Integer> taps) {
        StringBuilder cipher = new StringBuilder();
        List<Character> keyBits = new ArrayList<>();
        for (char bit : key.toCharArray()) keyBits.add(bit);

        for (char bit : plaintext.toCharArray()) {
            int xorVal = 0;
            for (int pos : taps) {
                xorVal ^= (keyBits.get(pos) - '0');
            }

            int keyBit = xorVal;
            int cipherBit = ((bit - '0') ^ keyBit);
            cipher.append(cipherBit);

            keyBits.add(0, (char) (keyBit + '0'));
            keyBits.remove(keyBits.size() - 1);
        }

        return cipher.toString();
    }

    public static String streamDecrypt(String ciphertext, String key, List<Integer> taps) {
        return streamEncrypt(ciphertext, key, taps);
    }

    public static String textToBits(String text) {
        StringBuilder bits = new StringBuilder();
        for (char ch : text.toCharArray()) {
            bits.append(String.format("%8s", Integer.toBinaryString(ch))
                    .replace(' ', '0'));
        }
        return bits.toString();
    }

    public static String bitsToText(String bits) {
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < bits.length(); i += 8) {
            if (i + 8 <= bits.length()) {
                String byteStr = bits.substring(i, i + 8);
                int val = Integer.parseInt(byteStr, 2);
                text.append((char) val);
            }
        }
        return text.toString();
    }
}