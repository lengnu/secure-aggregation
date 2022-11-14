package com.duwei.crypto.enc;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.enc
 * @Author: duwei
 * @Date: 2022/11/14 11:02
 * @Description: AES加密类
 */
public class AESCoder {
    //private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String AES_CIPHER_ALGORITHM = "AES";

    /**
     * 生成加密的初始向量s
     *
     * @param length
     * @param seed
     * @return
     */
    public static byte[] generateIV(int length, byte[] seed) {
        SecureRandom secureRandom = new SecureRandom(seed);
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static Key toKey(byte[] secretKey) throws NoSuchAlgorithmException {
        return new SecretKeySpec(secretKey, "AES");
    }

    public static byte[] encrypt(byte[] data, byte[] secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, toKey(secretKey));
        return cipher.doFinal(data);
    }

}
