package com.margular.aes;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.apache.commons.codec.digest.DigestUtils.sha256;

public class ECB {
    private int keySize;

    public ECB(int keySize) {
        if (keySize != 16 && keySize != 24 && keySize != 32) {
            throw new RuntimeException("key size should be 16 or 24 or 32!");
        }

        this.keySize = keySize;
    }

    public byte[] encrypt(byte[] stream, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = new byte[keySize];
        System.arraycopy(sha256(key), 0, keyBytes, 0, keySize);
        SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);

        return cipher.doFinal(stream);
    }

    public byte[] decrypt(byte[] stream, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] keyBytes = new byte[keySize];
        System.arraycopy(sha256(key), 0, keyBytes, 0, keySize);
        SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secret);

        return cipher.doFinal(stream);
    }
}
