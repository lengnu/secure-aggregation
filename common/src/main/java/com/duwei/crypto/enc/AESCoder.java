//package com.duwei.crypto.enc;
//
//import javax.crypto.Cipher;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.SecretKey;
//import java.security.NoSuchAlgorithmException;
//import java.security.SecureRandom;
//
///**
// * @BelongsProject: Secure-Aggregation
// * @BelongsPackage: com.duwei.crypto.enc
// * @Author: duwei
// * @Date: 2022/11/14 11:02
// * @Description: AES加密类
// */
//public class AESCoder {
//    private static final String AES_CIPHER_ALGORITHM = "AES/GCM/NoPadding";
//
//    /**
//     * 生成加密的初始向量s
//     * @param length
//     * @param seed
//     * @return
//     */
//    public static byte[] generateIV(int length,byte[] seed){
//        SecureRandom secureRandom = new SecureRandom(seed);
//        byte[] bytes = new byte[length];
//        secureRandom.nextBytes(bytes);
//        return bytes;
//    }
//
//
//    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException {
//        Cipher instance = Cipher.getInstance(AES_CIPHER_256);
//    }
//
//    public static byte[] encrypt(byte[] data,byte[] IV,byte)
//
//}
