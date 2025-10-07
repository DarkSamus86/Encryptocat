package org.darksamus86.Hash;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

public class Hash {

    private static final Pattern BIN_PATTERN = Pattern.compile("^[01]+$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]+$");
    private static final Pattern DEC_PATTERN = Pattern.compile("^\\d+$");

    // ----------------------- Публичный метод -----------------------
    public static String hash(String ivInput, String plainInput) {
        String ivBits = parseIvInput(ivInput);
        String bits = parsePlaintextToBits(plainInput);

        if (bits.isEmpty()) {
            throw new IllegalArgumentException("Пустой ввод — ничего хешировать.");
        }

        java.util.List<String> blocks = new java.util.ArrayList<>();
        int pos = 0;
        while (pos < bits.length()) {
            int end = Math.min(pos + 32, bits.length());
            blocks.add(bits.substring(pos, end));
            pos = end;
        }

        if (blocks.isEmpty()) {
            blocks.add("00000000000000000000000000000000");
        }

        String last = blocks.get(blocks.size() - 1);
        if (last.length() < 32) {
            last = String.format("%-32s", last).replace(' ', '0');
            blocks.set(blocks.size() - 1, last);
        }

        String state = ivBits;
        for (String blk : blocks) {
            state = compress32(state, blk);
        }

        return state;
    }

    // ----------------------- SPN Примитивы -----------------------

    private static String sboxLookup(String pair) {
        return switch (pair) {
            case "00" -> "10";
            case "01" -> "00";
            case "10" -> "11";
            case "11" -> "01";
            default -> throw new IllegalArgumentException("Bad sbox input: " + pair);
        };
    }

    private static String sboxSubstitution(String bits4) {
        String a = bits4.substring(0, 2);
        String b = bits4.substring(2, 4);
        return sboxLookup(a) + sboxLookup(b);
    }

    private static String permutation(String bits4) {
        if (bits4.length() != 4) throw new IllegalArgumentException("perm expects 4 bits");
        return "" + bits4.charAt(1) + bits4.charAt(0) + bits4.charAt(3) + bits4.charAt(2);
    }

    private static String roundEncrypt(String bits4, String key4, boolean lastRound) {
        int bv = Integer.parseInt(bits4, 2);
        int kv = Integer.parseInt(key4, 2);
        int xr = bv ^ kv;
        String xorRes = String.format("%4s", Integer.toBinaryString(xr & 0xF)).replace(' ', '0');
        String sOut = sboxSubstitution(xorRes);
        return lastRound ? sOut : permutation(sOut);
    }

    private static int spnEncrypt8bit(int P, int K) {
        String pBits = String.format("%8s", Integer.toBinaryString(P & 0xFF)).replace(' ', '0');
        String kBits = String.format("%8s", Integer.toBinaryString(K & 0xFF)).replace(' ', '0');

        String P1 = pBits.substring(0, 4);
        String P2 = pBits.substring(4);
        String K1 = kBits.substring(0, 4);
        String K2 = kBits.substring(4);

        String C1 = roundEncrypt(P1, K1, false);
        String C2 = roundEncrypt(C1, K2, true);
        String C3 = roundEncrypt(P2, K1, false);
        String C4 = roundEncrypt(C3, K2, true);

        String ciphertextBits = C2 + C4;
        return Integer.parseInt(ciphertextBits, 2) & 0xFF;
    }

    // ----------------------- Компрессия -----------------------

    private static String compress32(String state32, String block32) {
        if (state32.length() != 32 || block32.length() != 32) {
            throw new IllegalArgumentException("state32 and block32 must be 32 bits");
        }

        StringBuilder outBytes = new StringBuilder();
        java.util.Iterator<String> itState = chunkBits(state32, 8).iterator();
        java.util.Iterator<String> itBlock = chunkBits(block32, 8).iterator();

        while (itState.hasNext() && itBlock.hasNext()) {
            String sChunk = itState.next();
            String bChunk = itBlock.next();
            int sInt = Integer.parseInt(sChunk, 2);
            int bInt = Integer.parseInt(bChunk, 2);
            int outInt = spnEncrypt8bit(sInt, bInt);
            outBytes.append(String.format("%8s", Integer.toBinaryString(outInt & 0xFF)).replace(' ', '0'));
        }

        String tmp = outBytes.toString();
        int tmpInt = (int) (Long.parseLong(tmp, 2) & 0xffffffffL);
        int stateInt = (int) (Long.parseLong(state32, 2) & 0xffffffffL);
        int blockInt = (int) (Long.parseLong(block32, 2) & 0xffffffffL);

        int newStateInt = tmpInt ^ stateInt ^ blockInt;
        return String.format("%32s", Integer.toBinaryString(newStateInt & 0xffffffff)).replace(' ', '0');
    }

    // ----------------------- Вспомогательные -----------------------

    private static Iterable<String> chunkBits(String bitstr, final int n) {
        return () -> new java.util.Iterator<>() {
            int i = 0;
            public boolean hasNext() { return i < bitstr.length(); }
            public String next() {
                int start = i;
                i = Math.min(i + n, bitstr.length());
                return bitstr.substring(start, i);
            }
        };
    }

    private static String parseIvInput(String s) {
        s = s.trim();
        if (s.isEmpty()) throw new IllegalArgumentException("IV пустой");

        if (BIN_PATTERN.matcher(s).matches()) {
            if (s.length() > 32) throw new IllegalArgumentException("IV длиннее 32 бит");
            return String.format("%32s", s).replace(' ', '0');
        }

        if (s.toLowerCase().startsWith("0x")) {
            BigInteger val = new BigInteger(s.substring(2), 16);
            if (val.bitLength() > 32) throw new IllegalArgumentException("IV не влезает в 32 бита.");
            return String.format("%32s", val.toString(2)).replace(' ', '0');
        }

        if (HEX_PATTERN.matcher(s).matches() && s.matches(".*[a-fA-F].*")) {
            BigInteger val = new BigInteger(s, 16);
            if (val.bitLength() > 32) throw new IllegalArgumentException("IV не влезает в 32 бита.");
            return String.format("%32s", val.toString(2)).replace(' ', '0');
        }

        if (DEC_PATTERN.matcher(s).matches()) {
            BigInteger val = new BigInteger(s, 10);
            if (val.bitLength() > 32) throw new IllegalArgumentException("IV не влезает в 32 бита.");
            return String.format("%32s", val.toString(2)).replace(' ', '0');
        }

        throw new IllegalArgumentException("Неверный формат IV.");
    }

    private static String parsePlaintextToBits(String s) {
        s = s.trim();
        if (s.isEmpty()) return "";

        if (BIN_PATTERN.matcher(s).matches()) return s;

        if (s.toLowerCase().startsWith("0x")) {
            String hexpart = s.substring(2);
            if (hexpart.length() % 2 != 0) hexpart = "0" + hexpart;
            byte[] b = hexStringToByteArray(hexpart);
            return bytesToBits(b);
        }

        if (HEX_PATTERN.matcher(s).matches() && s.matches(".*[a-fA-F].*")) {
            if (s.length() % 2 != 0) s = "0" + s;
            byte[] b = hexStringToByteArray(s);
            return bytesToBits(b);
        }

        if (DEC_PATTERN.matcher(s).matches()) {
            BigInteger val = new BigInteger(s, 10);
            return val.equals(BigInteger.ZERO) ? "0" : val.toString(2);
        }

        return bytesToBits(s.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String bytesToBits(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte by : b) {
            sb.append(String.format("%8s", Integer.toBinaryString(by & 0xFF)).replace(' ', '0'));
        }
        return sb.toString();
    }
}
