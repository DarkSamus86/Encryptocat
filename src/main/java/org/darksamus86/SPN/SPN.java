package org.darksamus86.SPN;

public class SPN {
    // S-блок: 00->10, 01->00, 10->11, 11->01
    private final int[] SBOX = {0b10, 0b00, 0b11, 0b01};

    public int encrypt(int P, int K) {
        // делим на половины
        int P1 = (P >> 4) & 0xF; // старшие 4 бита
        int P2 = P & 0xF;        // младшие 4 бита
        int K1 = (K >> 4) & 0xF;
        int K2 = K & 0xF;

        // Левая часть: P1 -> K1 -> S -> perm -> K2 -> S -> perm
        int C1 = round(P1, K1, true);
        int C2 = round(C1, K2, true);

        // Правая часть: P2 -> K1 -> S -> perm -> K2 -> S (без perm!)
        int C3 = round(P2, K1, true);
        int C4 = round(C3, K2, false);

        // соединяем в итог
        return (C2 << 4) | C4;
    }

    private int round(int value, int key, boolean doPerm) {
        int res = xor(value, key);
        res = substitute(res);
        if (doPerm) res = permute(res);
        return res;
    }

    private int xor(int a, int b) {
        return a ^ b;
    }

    private int substitute(int halfWord) {
        // 4 бита -> две пары по 2 бита
        int left = (halfWord >> 2) & 0b11;
        int right = halfWord & 0b11;

        left = SBOX[left];
        right = SBOX[right];

        return (left << 2) | right;
    }

    private int permute(int halfWord) {
        // Перестановка: (1↔2, 3→3, 4→3?)
        // я понял так: [b1,b2,b3,b4] → [b2,b1,b3,b3]
        int b1 = (halfWord >> 3) & 1;
        int b2 = (halfWord >> 2) & 1;
        int b3 = (halfWord >> 1) & 1;
        int b4 = halfWord & 1;

        int newB1 = b2;
        int newB2 = b1;
        int newB3 = b3;
        int newB4 = b3; // т.к. "4 символ на 3 позицию"

        return (newB1 << 3) | (newB2 << 2) | (newB3 << 1) | newB4;
    }
}
