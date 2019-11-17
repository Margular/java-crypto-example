package com.margular.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.apache.commons.codec.digest.DigestUtils.sha256;

public class OFB {
    private int keySize;

    public OFB(int keySize) {
        if (keySize != 16 && keySize != 24 && keySize != 32) {
            throw new RuntimeException("key size should be 16 or 24 or 32!");
        }

        this.keySize = keySize;
    }

    public byte[] encrypt(byte[] stream, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // Generating IV.
        int ivSize = 16;
        byte[] iv = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Hashing key.
        byte[] keyBytes = new byte[keySize];
        System.arraycopy(sha256(key), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(stream);

        // Combine IV and encrypted part.
        byte[] encryptedIVAndText = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedIVAndText, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedIVAndText, iv.length, encrypted.length);

        return encryptedIVAndText;
    }

    public byte[] decrypt(byte[] stream, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        int ivSize = 16;
        int keySize = 16;

        // Extract IV.
        byte[] iv = new byte[ivSize];
        System.arraycopy(stream, 0, iv, 0, iv.length);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Extract encrypted part.
        int encryptedSize = stream.length - iv.length;
        byte[] encryptedBytes = new byte[encryptedSize];
        System.arraycopy(stream, iv.length, encryptedBytes, 0, encryptedSize);

        // Hash key.
        byte[] keyBytes = new byte[keySize];
        System.arraycopy(sha256(key), 0, keyBytes, 0, keyBytes.length);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Decrypt.
        Cipher cipher = Cipher.getInstance("AES/OFB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(encryptedBytes);
    }

    public static void main(String[] args) throws NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, DecoderException {
        byte[] plain = "1234567890123456111122223333444".getBytes();
        byte[] key = "Wow You are so sao!".getBytes();
        String ivHex = "ac9ca1e7fc2b80decc26de8b912cbc81";
        String cipherHex =
                "66120b13e75c0183699a1bdbd32f5d42" +
                "5630982c4c11600db41b94d71861bf0b";
        String ivAndCipherHex = ivHex + cipherHex;
        byte[] ivAndCipher = Hex.decodeHex(ivAndCipherHex);

//        System.out.println(Hex.encodeHex(new OFB(16).encrypt(plain, key)));
//        System.out.println(new String(new OFB(16).decrypt(ivAndCipher, key)));

        /*
         * origin:
         * 1234567890123456
         * 111122223333444
         *
         * we want:
         * a234567890123456
         * x1122223333444
         *
         * */

        byte[] cipher = Hex.decodeHex(cipherHex);
        cipher[0] = (byte) (cipher[0] ^ '1' ^ 'a');
        cipher[16] = (byte) (cipher[16] ^ '1' ^ 'x');
        String hackedCipherHex = Hex.encodeHexString(cipher);
        String hackedIvAndCipherHex = ivHex + hackedCipherHex;
        byte[] hackedIvAndCipher = Hex.decodeHex(hackedIvAndCipherHex);

        System.out.println(new String(new OFB(16).decrypt(hackedIvAndCipher, key)));
    }
}
