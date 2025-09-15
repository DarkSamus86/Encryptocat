package org.darksamus86.FeistelCipher;

public class FeistelCipher {
    private static final int NUM_ROUNDS = 16;

    public static String encrypt(String plaintext, String key) {
        // Convert the plaintext and key to binary strings
        String binaryPlaintext = stringToBinary(plaintext);
        String binaryKey = stringToBinary(key);

        // Split the binary plaintext into two halves
        String left = binaryPlaintext.substring(0, binaryPlaintext.length() / 2);
        String right = binaryPlaintext.substring(binaryPlaintext.length() / 2);

        // Perform Feistel rounds
        for (int i = 0; i < NUM_ROUNDS; i++) {
            String newLeft = right;
            String newRight = xor(left, feistelFunction(right, binaryKey));

            left = newLeft;
            right = newRight;
        }

        // Combine the left and right halves and convert back to plaintext
        String ciphertext = binaryToString(left + right);
        return ciphertext;
    }

    public static String decrypt(String ciphertext, String key) {
        // Convert the ciphertext and key to binary strings
        String binaryCiphertext = stringToBinary(ciphertext);
        String binaryKey = stringToBinary(key);

        // Split the binary ciphertext into two halves
        String left = binaryCiphertext.substring(0, binaryCiphertext.length() / 2);
        String right = binaryCiphertext.substring(binaryCiphertext.length() / 2);

        // Perform Feistel rounds in reverse order
        for (int i = NUM_ROUNDS - 1; i >= 0; i--) {
            String newRight = left;
            String newLeft = xor(right, feistelFunction(left, binaryKey));

            left = newLeft;
            right = newRight;
        }

        // Combine the left and right halves and convert back to plaintext
        String plaintext = binaryToString(left + right);
        return plaintext;
    }

    private static String feistelFunction(String input, String key) {
        // Perform some transformation on the input using the key
        // This can be any cryptographic function, such as XOR, substitution, permutation, etc.
        // For simplicity, we will use XOR as the Feistel function in this example
        return xor(input, key);
    }

    private static String xor(String a, String b) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < a.length(); i++) {
            if (a.charAt(i) == b.charAt(i)) {
                result.append("0");
            } else {
                result.append("1");
            }
        }
        return result.toString();
    }

    private static String stringToBinary(String str) {
        StringBuilder binary = new StringBuilder();
        for (char c : str.toCharArray()) {
            String binaryChar = Integer.toBinaryString(c);
            binary.append(String.format("%8s", binaryChar).replace(" ", "0"));
        }
        return binary.toString();
    }

    private static String binaryToString(String binary) {
        StringBuilder str = new StringBuilder();
        for (int i = 0; i < binary.length(); i += 8) {
            String binaryChar = binary.substring(i, i + 8);
            int decimal = Integer.parseInt(binaryChar, 2);
            str.append((char) decimal);
        }
        return str.toString();
    }
}
