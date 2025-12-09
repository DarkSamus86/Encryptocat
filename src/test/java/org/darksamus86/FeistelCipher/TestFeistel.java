package org.darksamus86.FeistelCipher;

import org.darksamus86.encryption_mode.EncryptionMode;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class TestFeistel {

    // --- вспомогательная функция для генерации ключа ---
    private String generateKeyHex() {
        String keyBits = EncryptionMode.generateKey(256);
        return EncryptionMode.bitsToHex(keyBits);
    }

    // ======================== БАЗОВЫЕ ТЕСТЫ =========================

    @Test
    void testEncryptDecryptSimpleText() {
        String key = generateKeyHex();
        String message = "Hello Feistel!";

        String cipher = FeistelCipher.encrypt(message, key);
        String decrypted = FeistelCipher.decrypt(cipher, key);

        assertEquals(message, decrypted, "Расшифрованный текст должен совпадать с исходным");
    }

    @Test
    void testEncryptDecryptEmptyString() {
        String key = generateKeyHex();
        String message = "";

        String cipher = FeistelCipher.encrypt(message, key);
        String decrypted = FeistelCipher.decrypt(cipher, key);

        assertEquals(message, decrypted, "Пустая строка должна корректно шифроваться/расшифровываться");
    }

    @Test
    void testEncryptDecryptLongString() {
        String key = generateKeyHex();
        String message = "A".repeat(5000); // длинная строка

        String cipher = FeistelCipher.encrypt(message, key);
        String decrypted = FeistelCipher.decrypt(cipher, key);

        assertEquals(message, decrypted, "Длинный текст должен корректно шифроваться и расшифровываться");
    }

    // ===================== ТЕСТЫ ДЛЯ БЛОКОВ ========================

    @Test
    void testEncryptDecryptBlock() {
        String keyBits = EncryptionMode.generateKey(256);
        String block = EncryptionMode.generateKey(512); // случайный блок 512 бит

        String encrypted = FeistelCipher.encryptBlock(block, keyBits);
        String decrypted = FeistelCipher.decryptBlock(encrypted, keyBits);

        assertEquals(block, decrypted,
                "Блок после decryptBlock должен полностью совпадать с исходным");
    }

    @Test
    void testBlockPaddingCorrectness() {
        String key = generateKeyHex();
        String message = "Short text";

        String bits = EncryptionMode.textToBits(message);
        List<String> blocks = EncryptionMode.splitIntoBlocks(bits, 512);

        for (String block : blocks) {
            assertTrue(block.length() <= 512);
        }

        // После шифрования/расшифрования padding должен исчезнуть в bitsToText()
        String cipher = FeistelCipher.encrypt(message, key);
        String decrypted = FeistelCipher.decrypt(cipher, key);

        assertEquals(message, decrypted, "Padding не должен влиять на восстановление текста");
    }

    // ===================== ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ ========================

    @Test
    void testEncryptProducesDifferentOutput() {
        String key = generateKeyHex();
        String message = "AAAAAA";

        String cipher1 = FeistelCipher.encrypt(message, key);
        String cipher2 = FeistelCipher.encrypt(message, key);

        // Детерминированный Feistel, так что должно быть одинаково
        assertEquals(cipher1, cipher2,
                "При фиксированном ключе и одинаковом тексте шифр должен совпадать");
    }

    @Test
    void testDecryptWithWrongKeyFails() {
        String key1 = generateKeyHex();
        String key2 = generateKeyHex();

        String message = "Sensitive data";

        String cipher = FeistelCipher.encrypt(message, key1);
        String decrypted = FeistelCipher.decrypt(cipher, key2);

        assertNotEquals(message, decrypted,
                "Расшифровка неверным ключом НЕ должна выдавать исходное сообщение");
    }
}
