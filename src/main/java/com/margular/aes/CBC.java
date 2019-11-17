package com.margular.aes;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.apache.commons.codec.digest.DigestUtils.sha256;

public class CBC {
    private int keySize;

    public CBC(int keySize) {
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
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

        return cipher.doFinal(encryptedBytes);
    }

    private boolean tryDecrypt(byte[] stream, byte[] key) {
        try {
            decrypt(stream, key);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException |
                InvalidAlgorithmParameterException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            return false;
        }

        return true;
    }

    // 字节反转攻击
    // Oracle padding attack
    public static void main(String[] args) throws NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            DecoderException, IOException {
        byte[] plain = "1234567890123456111122223333444".getBytes();
        byte[] key = "Wow You are so sao!".getBytes();
        String ivHex = "61e29a4c83f82e620438554a08d7d79c";
        String cipherHex =
                "af6e97506676ca6117da6677ba5282b1" +
                "ebd3823a4b2aee73679ca1e1f01baa1f";
        String ivAndCipherHex = ivHex + cipherHex;
        byte[] ivAndCipher = Hex.decodeHex(ivAndCipherHex);

//        System.out.println(Hex.encodeHex(new CBC(16).encrypt(plain, key)));
//        System.out.println(new String(new CBC(16).decrypt(ivAndCipher, key)));

        /*
        * origin:
        * 1234567890123456
        * 111122223333444
        *
        * we want:
        * @@@@@@@@@@@@@@@(what ever)
        * 121122223333444
        *
        * we need to change cipher at 2nd @ position
        * */

        byte[] cipher = Hex.decodeHex(cipherHex);
        cipher[1] = (byte) (cipher[1] ^ '1' ^ '2');
        String hackedCipherHex = Hex.encodeHexString(cipher);
        String hackedIvAndCipherHex = ivHex + hackedCipherHex;
        byte[] hackedIvAndCipher = Hex.decodeHex(hackedIvAndCipherHex);

//        System.out.println(new String(new CBC(16).decrypt(hackedIvAndCipher, key)));

        // Oracle padding attack
        byte[] c0 = new byte[16];
        System.arraycopy(Hex.decodeHex(ivHex), 0, c0, 0, 16);
        cipher = Hex.decodeHex(cipherHex);
        int index = 0;
        byte[] cipher_slice = new byte[16];
        while (index < cipher.length) {
            System.arraycopy(cipher, index, cipher_slice, 0,16);
            byte[] iv2 = Hex.decodeHex("00000000000000000000000000000000");
            byte[] raw = new byte[16];
            byte[] inter = new byte[16];
            // decrypt cipher slice
            for (int pos = 15; pos >= 0; pos--) {
                // set position pos----end to padding value
                byte paddingValue = (byte) (16 - pos);
                for (int i = pos + 1; i < 16; i++) {
                    iv2[i] = (byte) (paddingValue ^ inter[i]);
                }

                while (true) {
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    outputStream.write(iv2);
                    outputStream.write(cipher_slice);
                    byte[] try_cipher = outputStream.toByteArray();
                    if (!new CBC(16).tryDecrypt(try_cipher, key)) {
                        // not correct
                        iv2[pos]++;
                        if (iv2[pos] == 0x00) {
                            throw new RuntimeException("can't find valid iv");
                        }
                    } else {
                        // correct
                        inter[pos] = (byte) (paddingValue ^ iv2[pos]);
                        raw[pos] = (byte) (inter[pos] ^ c0[pos]);
                        break;
                    }
                }
            }

            System.out.println(new String(raw));
            index += 16;
            System.arraycopy(cipher, index - 16, c0, 0, 16);
        }
    }
}
