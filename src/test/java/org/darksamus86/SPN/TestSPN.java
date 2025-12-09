package org.darksamus86.SPN;

import org.junit.jupiter.api.Test;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.darksamus86.encryption_mode.EncryptionMode.*;   // <-- ВАЖНО!

class TestSPN {

    // Проверка генерации ключа нужной длины
    @Test
    void testKeyGenerationLength() {
        String key = generateKey(256);
        assertEquals(256, key.length(), "Ключ должен иметь длину 256 бит");
        assertTrue(key.matches("[01]+"), "Ключ должен содержать только биты (0/1)");
    }

    // Проверка обратимости конвертации бит ↔ HEX
    @Test
    void testBitsToHexAndBack() {
        String bits = "1100101011110000";
        String hex = bitsToHex(bits);
        String restored = hexToBits(hex);
        assertEquals(bits, restored, "Конвертация бит → HEX → биты должна быть обратимой");
    }

    // Проверка S-box и обратного S-box
    @Test
    void testSboxSubstitutionAndInverse() {
        String input = "1100110000001111";
        String substituted = sboxSubstitution4bit(input, false);
        String restored = sboxSubstitution4bit(substituted, true);
        assertEquals(input, restored, "S-box и обратный S-box должны быть взаимно обратимыми");
    }

    // Проверка P-box и обратного P-box
    @Test
    void testPboxPermutationAndInverse() {
        String input = "1100110000001111";
        String permuted = pboxPermutation(input, false, null, input.length());
        String restored = pboxPermutation(permuted, true, null, permuted.length());
        assertEquals(input, restored, "P-box и обратный P-box должны быть взаимно обратимыми");
    }

    // Проверка паддинга PKCS#7
    @Test
    void testPkcs7PadAndUnpad() {
        String bits = "01010100"; // 8 bit
        String padded = pkcs7Pad(bits, 128);
        String unpadded = pkcs7Unpad(padded);

        assertEquals(bits, unpadded, "Данные должны полностью восстанавливаться");
        assertEquals(0, padded.length() % 128, "Паддинг должен выравнивать длину до 128 бит");
    }

    // Проверка XOR
    @Test
    void testXorBits() {
        String a = "1100";
        String b = "1010";
        String result = xorBits(a, b);
        assertEquals("0110", result, "XOR должен работать побитово");
    }

    // Основной тест: encryptBlock/decryptBlock
    @Test
    void testEncryptBlockAndDecryptBlock() {

        String key256 = generateKey(256);
        String K1 = key256.substring(0, 128);
        String K2 = key256.substring(128);
        List<String> roundKeys = List.of(K1, K2, K1, K2);

        String plaintext = "HELLO";

        String bits = detectAndConvertToBits(plaintext);
        bits = pkcs7Pad(bits, 512);

        // Шифрование
        String cipherBits = SPN.encryptBlock(bits.substring(0, 512), roundKeys);
        assertNotEquals(bits.substring(0, 512), cipherBits, "Блок шифруется, должен измениться");

        // Расшифрование
        String decryptedBits = SPN.decryptBlock(cipherBits, roundKeys);
        String unpaddedBits = pkcs7Unpad(decryptedBits);

        String decrypted = bitsToText(unpaddedBits).replace("\0", "").trim();
        assertEquals(plaintext, decrypted, "Исходный и расшифрованный текст должны совпадать");
    }

    // ECB режим
    @Test
    void testECBEncryptDecrypt() {
        String key256 = generateKey(256);
        String K1 = key256.substring(0, 128);
        String K2 = key256.substring(128);
        List<String> roundKeys = List.of(K1, K2, K1, K2);

        String plaintext = "TEST ECB MODE";
        String bits = detectAndConvertToBits(plaintext);
        bits = pkcs7Pad(bits, 512);

        String cipherBits = SPN.ecbEncrypt(bits, roundKeys);
        String restoredBits = SPN.ecbDecrypt(cipherBits, roundKeys);

        String unpadded = pkcs7Unpad(restoredBits);
        String restored = bitsToText(unpadded).replace("\0", "").trim();

        assertEquals(plaintext, restored);
    }

    // CBC режим
    @Test
    void testCBCEncryptDecrypt() {
        String key256 = generateKey(256);
        String K1 = key256.substring(0, 128);
        String K2 = key256.substring(128);
        List<String> roundKeys = List.of(K1, K2, K1, K2);

        String plaintext = "TEST CBC MODE";
        String bits = detectAndConvertToBits(plaintext);
        bits = pkcs7Pad(bits, 512);

        String iv = generateIV(128);

        String cipherBits = SPN.cbcEncrypt(bits, roundKeys, iv);
        String restoredBits = SPN.cbcDecrypt(cipherBits, roundKeys, iv);

        String unpadded = pkcs7Unpad(restoredBits);
        String restored = bitsToText(unpadded).replace("\0", "").trim();

        assertEquals(plaintext, restored);
    }
}
