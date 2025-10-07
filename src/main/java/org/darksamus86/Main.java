package org.darksamus86;

import org.darksamus86.FeistelCipher.FeistelCipher;
import org.darksamus86.Hash.Hash;

import java.math.BigInteger;

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
    }
}