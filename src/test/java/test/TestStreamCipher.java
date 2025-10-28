package test;

import org.darksamus86.StreamCipher.StreamCipher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

public class TestStreamCipher {
    @Test
    void testDetectKeyFormat() {
        Assertions.assertEquals("binary", StreamCipher.detectKeyFormat("101010"));
        assertEquals("decimal", StreamCipher.detectKeyFormat("12345"));
        assertEquals("hex", StreamCipher.detectKeyFormat("0x1A3F"));
        assertEquals("hex", StreamCipher.detectKeyFormat("ABCDEF"));
        assertEquals("text", StreamCipher.detectKeyFormat("Hello"));
    }

    @Test
    void testToBinary() {
        assertEquals("1010", StreamCipher.toBinary("1010"));
        assertEquals("1100", StreamCipher.toBinary("12")); // 12 -> 1100
        assertEquals("1111011", StreamCipher.toBinary("0x7B")); // 0x7B -> 123 -> 1111011

        String textBinary = StreamCipher.toBinary("A"); // 'A' = 65 -> 01000001
        assertEquals("01000001", textBinary);
    }

    @Test
    void testGenerateTaps() {
        List<Integer> taps = StreamCipher.generateTaps(8, 3);
        assertEquals(3, taps.size());
        assertTrue(taps.stream().allMatch(pos -> pos >= 0 && pos < 8));
    }

    @Test
    void testStreamEncryptAndDecrypt() {
        String key = "11001010";
        List<Integer> taps = List.of(1, 3, 5);
        String plaintext = "10110011";

        String cipher = StreamCipher.streamEncrypt(plaintext, key, taps);
        assertNotNull(cipher);
        assertEquals(plaintext.length(), cipher.length());

        String decrypted = StreamCipher.streamDecrypt(cipher, key, taps);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void testTextToBitsAndBitsToText() {
        String text = "Hi";
        String bits = StreamCipher.textToBits(text);
        assertEquals("0100100001101001", bits);

        String recovered = StreamCipher.bitsToText(bits);
        assertEquals(text, recovered);
    }

    @Test
    void testFullEncryptionCycle() {
        String key = "10101010";
        List<Integer> taps = List.of(0, 2, 5);
        String plaintext = "Hello";

        String plaintextBits = StreamCipher.textToBits(plaintext);
        String keyBits = StreamCipher.toBinary(key);

        String cipherBits = StreamCipher.streamEncrypt(plaintextBits, keyBits, taps);
        String decryptedBits = StreamCipher.streamDecrypt(cipherBits, keyBits, taps);
        String decryptedText = StreamCipher.bitsToText(decryptedBits);

        assertEquals(plaintext, decryptedText);
    }
}
