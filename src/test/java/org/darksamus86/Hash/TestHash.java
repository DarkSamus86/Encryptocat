package org.darksamus86.Hash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TestHash {

    // ------------------- BASIC HASH TESTS -------------------

    @Test
    void testSimpleHashText() {
        String iv = "00000000000000000000000000000001";
        String plaintext = "A"; // 0x41
        String hash = Hash.hash(iv, plaintext);

        assertNotNull(hash);
        assertEquals(32, hash.length());
        assertTrue(hash.matches("[01]+"), "Hash must be binary");
    }

    @Test
    void testSimpleHashHexPlaintext() {
        String iv = "0x1";
        String plaintext = "0x41"; // 'A'
        String hash = Hash.hash(iv, plaintext);

        assertNotNull(hash);
        assertEquals(32, hash.length());
        assertTrue(hash.matches("[01]+"));
    }

    @Test
    void testSimpleHashBinaryPlaintext() {
        String iv = "1010";
        String plaintext = "01010101";
        String hash = Hash.hash(iv, plaintext);

        assertNotNull(hash);
        assertEquals(32, hash.length());
    }

    @Test
    void testDifferentInputsProduceDifferentHashes() {
        String iv = "1";
        String h1 = Hash.hash(iv, "abc");
        String h2 = Hash.hash(iv, "abd");

        assertNotEquals(h1, h2, "Different plaintexts must produce different hashes");
    }

    @Test
    void testSameInputProducesSameOutput() {
        String iv = "0x1234abcd";
        String p = "hello";

        String h1 = Hash.hash(iv, p);
        String h2 = Hash.hash(iv, p);

        assertEquals(h1, h2, "Hash must be deterministic");
    }

    // ------------------- IV PARSING -------------------

    @Test
    void testIvHex() {
        String h = Hash.hash("0xFF", "test");
        assertEquals(32, h.length());
    }

    @Test
    void testIvDecimal() {
        String h = Hash.hash("255", "test");
        assertEquals(32, h.length());
    }

    @Test
    void testIvBinary() {
        String h = Hash.hash("10101010", "test");
        assertEquals(32, h.length());
    }

    @Test
    void testIvTooLong() {
        assertThrows(IllegalArgumentException.class, () ->
                Hash.hash("111100001111000011110000111100001", "test")
        );
    }

    @Test
    void testIvEmpty() {
        assertThrows(IllegalArgumentException.class, () ->
                Hash.hash("", "abc")
        );
    }

    // ------------------- PLAINTEXT PARSING -------------------

    @Test
    void testPlaintextEmptyGivesError() {
        assertThrows(IllegalArgumentException.class, () ->
                Hash.hash("1", "")
        );
    }

    @Test
    void testPlaintextHex() {
        String h = Hash.hash("1", "0x41");
        assertEquals(32, h.length());
    }

    @Test
    void testPlaintextBinary() {
        String h = Hash.hash("1", "01010101");
        assertEquals(32, h.length());
    }

    @Test
    void testPlaintextDecimal() {
        String h = Hash.hash("1", "255");
        assertEquals(32, h.length());
    }

    @Test
    void testPlaintextUtf8() {
        String h = Hash.hash("1", "Привет");
        assertEquals(32, h.length());
    }

    // ------------------- BLOCK SPLITTING -------------------

    @Test
    void testPlaintextPadding() {
        String h = Hash.hash("1", "a"); // 1 byte = 8 bits -> padded to 32 bits
        assertEquals(32, h.length());
    }

    @Test
    void testMultipleBlocks() {
        // 5 chars → 40 bits → 2 blocks
        String h = Hash.hash("1", "Hello");
        assertEquals(32, h.length());
    }

    // ------------------- ERROR CONDITIONS -------------------

    @Test
    void testLongDecimalPlaintextIsOk() {
        // Big numbers must convert to binary
        String h = Hash.hash("1", "999999999");
        assertEquals(32, h.length());
    }

    @Test
    void testBadIvFormat() {
        assertThrows(IllegalArgumentException.class, () ->
                Hash.hash("IV_BAD", "abc")
        );
    }

    @Test
    void testBadPlaintextFormat() {
        assertDoesNotThrow(() ->
                Hash.hash("1", "???") // gets encoded as UTF-8 → valid
        );
    }
}
