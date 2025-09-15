package org.darksamus86;

import org.darksamus86.FeistelCipher.FeistelCipher;

public class Main {
    public static void main(String[] args) {
        String plaintext = "Hello, World!";
        String key = "secretkey";

        // Encrypt the plaintext
        String ciphertext = FeistelCipher.encrypt(plaintext, key);
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the ciphertext
        String decryptedPlaintext = FeistelCipher.decrypt(ciphertext, key);
        System.out.println("Decrypted plaintext: " + decryptedPlaintext);
    }
}