package com.margular.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

class OFBTest {

    @Test
    void encrypt() {
        String[][] samples = {
                {"123456789012345",         "1234567890123456"},
                {"123456789012346",         "1234567890123456"},
                {"123456789012345601234",   "1234567890123456"},
                {"123456789012345601235",   "1234567890123456"},
        };

        System.out.println("AES OFB mode encrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(Hex.encodeHexString(
                        new OFB(16).encrypt(sample[0].getBytes(), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    void decrypt() {
        String[][] samples = {
                {"564b80da18632ebf7c8af3741649b9fa559137d3ea8f1bf5ac8d58ff558e8440", "1234567890123456"},
                {"3d33a9b1b376d1104ec6ef67094c624e7ea76f79ed1b6bcaa90ab7a1c4549788", "1234567890123456"},
                {"adb3a79d251e6e58eff1c352b264412574ce780e7b9dc0bba14eb873430e8ebdea0f53477f2d5b13e18e56758c3da862",
                        "1234567890123456"},
                {"397481215854d8dfaa7a6a227b3147651311b67f8c01cce6e93c722b7ce9eba2849f9a04711bf04f088183f0030db3af",
                        "1234567890123456"},
        };

        System.out.println("AES OFB mode decrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(new String(
                        new OFB(16).decrypt(Hex.decodeHex(sample[0]), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException | InvalidAlgorithmParameterException | DecoderException e) {
                e.printStackTrace();
            }
        }
    }
}