package org.darksamus86;

import org.darksamus86.FeistelCipher.FeistelCipher;
import org.darksamus86.Hash.Hash;
import org.darksamus86.StreamCipher.StreamCipher;
import org.darksamus86.EDS.EDS;
import org.darksamus86.RSA.RSA;

import java.math.BigInteger;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        String plaintext = "Hello, World!";
        String key = "secretkey";


        // Feistel
        // Encrypt the plaintext
        String ciphertext = FeistelCipher.encrypt(plaintext, key);
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the ciphertext
        String decryptedPlaintext = FeistelCipher.decrypt(ciphertext, key);
        System.out.println("Decrypted plaintext: " + decryptedPlaintext);

        // Hash
        String iv = "0x12345678";
        String hash = Hash.hash(iv, plaintext);

        System.out.println("IV: " + iv);
        System.out.println("Plaintext: " + plaintext);
        System.out.println("Hash (bin): " + hash);
        System.out.println("Hash (hex): 0x" + String.format("%08x", new BigInteger(hash, 2).intValue()));

        // Stream Cipher
        String key1 = StreamCipher.toBinary("0x1234");
        List<Integer> taps = StreamCipher.generateTaps(key.length(), 3);

        String text = "Hello";
        String plaintext1 = StreamCipher.textToBits(text);

        String cipher = StreamCipher.streamEncrypt(plaintext1, key1, taps);
        String decryptedBits = StreamCipher.streamDecrypt(cipher, key1, taps);
        String decryptedText = StreamCipher.bitsToText(decryptedBits);

        System.out.println("Key bits: " + key1);
        System.out.println("Taps: " + taps);
        System.out.println("Cipher bits: " + cipher);
        System.out.println("Decrypted text: " + decryptedText);

        // EDS
        try {
            EDS eds = new EDS();

            String message = "Hello from EDS";
            byte[] signature = eds.signMessage(message);

            System.out.println("Сообщение: " + message);
            System.out.println("Подпись (hex): " + EDS.toHex(signature));
            System.out.println("Подпись верна: " + eds.verifyMessage(message, signature));

            System.out.println("\nПубличный ключ (PEM):\n" + eds.getPublicKeyPem());
        } catch (Exception e) {
            e.printStackTrace();
        }

        // RSA
        String[] keys = RSA.generateKeys();
        String publicKey = keys[0];   // e,n
        String privateKey = keys[1];  // d,n

        System.out.println("Открытый ключ: " + publicKey);
        System.out.println("Закрытый ключ: " + privateKey);

        // Пример шифрования
        String message = "Hello RSA!";
        String[] pubParts = publicKey.split(",");
        long e = Long.parseLong(pubParts[0]);
        long n = Long.parseLong(pubParts[1]);

        String cipherRsa = RSA.encrypt(message, e, n);
        System.out.println("\nЗашифрованное сообщение (hex): " + cipherRsa);

        // Пример расшифровки
        String[] privParts = privateKey.split(",");
        long d = Long.parseLong(privParts[0]);
        long n2 = Long.parseLong(privParts[1]);

        String decrypted = RSA.decrypt(cipherRsa, d, n2);
        System.out.println("Расшифрованное сообщение: " + decrypted);
    }
}