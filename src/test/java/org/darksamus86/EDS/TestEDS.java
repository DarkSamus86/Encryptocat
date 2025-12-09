package org.darksamus86.EDS;

import org.darksamus86.RSA.RSA;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TestEDS {

    @Test
    void testSignAndVerify() {
        String[] keys = RSA.generateKeys();
        String pub = keys[0];
        String priv = keys[1];

        EDS eds = new EDS(pub, priv);

        String message = "Hello EDS";
        String signature = eds.signMessage(message);

        assertTrue(eds.verifyMessage(message, signature),
                "Подпись должна успешно проверяться");
    }

    @Test
    void testVerifyFailsOnModifiedMessage() {
        String[] keys = RSA.generateKeys();
        EDS eds = new EDS(keys[0], keys[1]);

        String msg = "Original";
        String signature = eds.signMessage(msg);

        String modifiedMsg = "Original!";

        assertFalse(eds.verifyMessage(modifiedMsg, signature),
                "Подпись НЕ должна проверяться, если сообщение изменено");
    }

    @Test
    void testVerifyFailsOnModifiedSignature() {
        String[] keys = RSA.generateKeys();
        EDS eds = new EDS(keys[0], keys[1]);

        String msg = "Secure";
        String signature = eds.signMessage(msg);

        // портим подпись: меняем последний символ
        String fakeSignature = signature.substring(0, signature.length() - 1) + "f";

        assertFalse(eds.verifyMessage(msg, fakeSignature),
                "Подпись НЕ должна проверяться, если подпись была изменена");
    }

    @Test
    void testDifferentKeysDoNotValidate() {
        String[] keys1 = RSA.generateKeys();
        String[] keys2 = RSA.generateKeys();

        EDS signer = new EDS(keys1[0], keys1[1]);   // подписываем
        EDS verifier = new EDS(keys2[0], keys2[1]); // проверяем другим ключом

        String msg = "Message";
        String signature = signer.signMessage(msg);

        assertFalse(verifier.verifyMessage(msg, signature),
                "Подпись НЕ должна проверяться под другим публичным ключом");
    }

    @Test
    void testSameMessageSameSignature() {
        String[] keys = RSA.generateKeys();
        EDS eds = new EDS(keys[0], keys[1]);

        String msg = "Repeat";

        String sig1 = eds.signMessage(msg);
        String sig2 = eds.signMessage(msg);

        assertEquals(sig1, sig2,
                "Одинаковое сообщение должно давать одинаковую подпись (детерминированность)");
    }
}
