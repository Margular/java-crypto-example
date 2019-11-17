package com.margular.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

class ECBTest {
    @Test
    void encrypt() {
        String[][] samples = {
                {"123456789012345", "1234567890123456"},
                {"123456789012346", "1234567890123456"},
                {"123456789012345601234", "1234567890123456"},
                {"123456789012345601235", "1234567890123456"},
        };

        System.out.println("AES ECB mode encrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(Hex.encodeHexString(
                        new ECB(16).encrypt(sample[0].getBytes(), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    void decrypt() {
        String[][] samples = {
                {"ea8bf6b0e08134365561625e8c6886bb", "1234567890123456"},
                {"94e231e9084aaf1a6a41a2fd1ecdbb3b", "1234567890123456"},
                {"ed6a1d6c39b3ec0a23066156f9b00f2a1033655effff7294dac99661c982aadc", "1234567890123456"},
                {"ed6a1d6c39b3ec0a23066156f9b00f2aecd8e9d570de4fad2caada30f1250f26", "1234567890123456"},
        };

        System.out.println("AES ECB mode decrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(new String(
                        new ECB(16).decrypt(Hex.decodeHex(sample[0]), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException | DecoderException e) {
                e.printStackTrace();
            }
        }
    }
}
