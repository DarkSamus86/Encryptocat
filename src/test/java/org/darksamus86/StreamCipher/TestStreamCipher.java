package org.darksamus86.StreamCipher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TestStreamCipher {

    @Test
    void testTextToBits() {
        assertEquals("0100100001101001",
                StreamCipher.textToBits("Hi"));
        assertEquals("0100000101000010",
                StreamCipher.textToBits("AB"));
    }

    @Test
    void testBitsToText() {
        assertEquals("Hi",
                StreamCipher.bitsToText("0100100001101001"));
        assertEquals("AB",
                StreamCipher.bitsToText("0100000101000010"));
    }

    @Test
    void testBitsToHex() {
        assertEquals("4a", StreamCipher.bitsToHex("01001010"));
        assertEquals("0f", StreamCipher.bitsToHex("00001111"));
        assertEquals("1", StreamCipher.bitsToHex("0001"));  // проверка padding
    }

    @Test
    void testHexToBits() {
        assertEquals("1010", StreamCipher.hexToBits("a"));
        assertEquals("11110000", StreamCipher.hexToBits("f0"));
    }

    @Test
    void testGenerateKey() {
        String key = StreamCipher.generateKey(256);

        assertEquals(256, key.length());
        assertTrue(key.matches("[01]+"));
    }

    @Test
    void testInitRegisters() {
        int[][] regs = StreamCipher.initRegisters("101010");

        assertEquals(StreamCipher.R1_LEN, regs[0].length);
        assertEquals(StreamCipher.R2_LEN, regs[1].length);
        assertEquals(StreamCipher.R3_LEN, regs[2].length);
    }

    @Test
    void testFlowSize() {
        int[][] regs = StreamCipher.initRegisters(StreamCipher.generateKey(64));

        String stream = StreamCipher.flow(
                regs[0], regs[1], regs[2],
                128
        );

        assertEquals(128, stream.length());
        assertTrue(stream.matches("[01]+"));
    }

    @Test
    void testEncryptionDecryptionSymmetry() {
        String keyBits = StreamCipher.generateKey(128);
        String plaintext = "Hello world";

        // шифруем
        String cipherBits = StreamCipher.a5Process(plaintext, keyBits);

        // расшифровываем (та же функция!)
        String decryptedBits = StreamCipher.a5Process(
                StreamCipher.bitsToText(cipherBits),   // text input required
                keyBits
        );

        // но a5Process принимает текст → нужно корректно подать чистые биты
        // поэтому сделаем правильную расшифровку вручную:

        int[][] regs = StreamCipher.initRegisters(keyBits);
        String ks = StreamCipher.flow(
                regs[0], regs[1], regs[2],
                cipherBits.length()
        );

        StringBuilder plainBits = new StringBuilder();
        for (int i = 0; i < cipherBits.length(); i++)
            plainBits.append((cipherBits.charAt(i) - '0') ^ (ks.charAt(i) - '0'));

        String decrypted = StreamCipher.bitsToText(plainBits.toString());

        assertEquals(plaintext, decrypted);
    }

    @Test
    void testFullCycleThroughHex() {
        String plaintext = "Test123";
        String keyBits = StreamCipher.generateKey(256);

        // encrypt
        String cipherBits = StreamCipher.a5Process(plaintext, keyBits);
        String cipherHex = StreamCipher.bitsToHex(cipherBits);
        String keyHex = StreamCipher.bitsToHex(keyBits);

        // decrypt
        String cipherBits2 = StreamCipher.hexToBits(cipherHex);
        String keyBits2 = StreamCipher.hexToBits(keyHex);
        keyBits2 = String.format("%256s", keyBits2).replace(' ', '0');

        int[][] regs = StreamCipher.initRegisters(keyBits2);
        String ks = StreamCipher.flow(regs[0], regs[1], regs[2], cipherBits2.length());

        StringBuilder plainBits = new StringBuilder();
        for (int i = 0; i < cipherBits2.length(); i++)
            plainBits.append((cipherBits2.charAt(i) - '0') ^ (ks.charAt(i) - '0'));

        String decrypted = StreamCipher.bitsToText(plainBits.toString());

        assertEquals(plaintext, decrypted);
    }
}
