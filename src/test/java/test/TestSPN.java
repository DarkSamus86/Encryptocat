package test;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import org.darksamus86.SPN.SPN;

import java.util.List;

public class TestSPN {
    @Test
    void testKeyGenerationLength() {
        String key = SPN.generateKey(256);
        assertEquals(256, key.length(), "Ключ должен иметь длину 256 бит");
    }

    @Test
    void testBitsToHexAndBack() {
        String bits = "1100101011110000";
        String hex = SPN.bitsToHex(bits);
        String restored = SPN.hexToBits(hex);
        assertEquals(bits, restored, "Конвертация бит → HEX → биты должна быть обратимой");
    }

    @Test
    void testSboxSubstitutionAndInverse() {
        String input = "1100110000001111";
        String substituted = SPN.sboxSubstitution4bit(input, false);
        String restored = SPN.sboxSubstitution4bit(substituted, true);
        assertEquals(input, restored, "S-box и обратный S-box должны быть взаимно обратимыми");
    }

    @Test
    void testPboxPermutationAndInverse() {
        String input = "1100110000001111";
        String permuted = SPN.pboxPermutation(input, false);
        String restored = SPN.pboxPermutation(permuted, true);
        assertEquals(input, restored, "P-box и обратный P-box должны быть взаимно обратимыми");
    }

    @Test
    void testPkcs7PadAndUnpad() {
        String bits = "01010100"; // 8 бит = 1 байт
        String padded = SPN.pkcs7Pad(bits, 128);
        String unpadded = SPN.pkcs7Unpad(padded);
        assertEquals(bits, unpadded, "После паддинга и удаления паддинга данные должны совпадать");
    }

    @Test
    void testXorBits() {
        String a = "1100";
        String b = "1010";
        assertEquals("0110", SPN.xorBits(a, b), "XOR должен корректно работать побитово");
    }

    @Test
    void testEncryptAndDecrypt() {
        // Исходные данные
        String key256 = SPN.generateKey(256);
        String K1 = key256.substring(0, 128);
        String K2 = key256.substring(128);
        List<String> roundKeys = List.of(K1, K2, K1, K2);

        String plaintext = "HELLO";
        String bits = SPN.detectAndConvertToBits(plaintext);
        bits = SPN.pkcs7Pad(bits, 512);

        // Шифрование
        String cipherBits = SPN.encrypt(bits.substring(0, 512), roundKeys);
        assertNotEquals(bits.substring(0, 512), cipherBits, "Шифртекст должен отличаться от исходных данных");

        // Расшифрование
        String decryptedBits = SPN.decrypt(cipherBits, roundKeys);
        String unpaddedBits = SPN.pkcs7Unpad(decryptedBits);
        String decryptedText = SPN.bitsToText(unpaddedBits).replace("\0", "").trim();

        assertEquals(plaintext, decryptedText, "Дешифрованный текст должен совпадать с исходным");
    }
}
