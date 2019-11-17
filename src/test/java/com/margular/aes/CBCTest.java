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
import java.util.Arrays;

class CBCTest {

    @Test
    void encrypt() {
        String[][] samples = {
                {"123456789012345",         "1234567890123456"},
                {"123456789012346",         "1234567890123456"},
                {"123456789012345601234",   "1234567890123456"},
                {"123456789012345601235",   "1234567890123456"},
        };

        System.out.println("AES CBC mode encrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(Hex.encodeHexString(
                        new CBC(16).encrypt(sample[0].getBytes(), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    void decrypt() {
        String[][] samples = {
                {"a3030c6185ef56e6dea951a06fb84d7b28e725c92682517e2ae31f46181d3231", "1234567890123456"},
                {"c702eee707bd2f0842fa51a7e186abbea24691ea076a8ee07ea763ba15a255dc", "1234567890123456"},
                {"fc38bea73349e0d5782ec3b4b7d3a813a77728fbc2cf69e6b5392647b54eb6380507c69d95deb8775e733c0a89e7b8b0",
                        "1234567890123456"},
                {"e23bfd06dc73dba0a6159a0e9bc31fc1508d90f0f31bc70a1d5570ff54b39cf2e01f7b6f0eb17b567dad4bf40fb39036",
                        "1234567890123456"},
        };

        System.out.println("AES CBC mode decrypt test:");
        for (String[] sample : samples) {
            try {
                System.out.println(new String(
                        new CBC(16).decrypt(Hex.decodeHex(sample[0]), sample[1].getBytes())));
            } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException |
                    IllegalBlockSizeException | InvalidAlgorithmParameterException | DecoderException e) {
                e.printStackTrace();
            }
        }
    }
}
