package com.duwei.crypto.aggrement;

import com.duwei.crypto.common.Constant;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.aggrement
 * @Author: duwei
 * @Date: 2022/11/10 9:17
 * @Description: DH密钥协商
 */
public class DHAggrement {

    private static final String DH_KEY = "DH";
    private static final int DH_KEY_LENGTH = Constant.DH_KEY_BIT_LENGTH;

    private static final String CIPHER_KEY = "AES";
    private static final int CIPHER_KEY_LENGTH = Constant.AES_KEY_BIT_LENGTH;
    private static final String CIPHER_MODE = Constant.AES_CIPHER_MODE;

    /**
     * 生成本地DH密钥对
     *
     * @return
     * @throws Exception
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH_KEY);
        keyPairGenerator.initialize(DH_KEY_LENGTH);
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 构建共享密钥
     *
     * @param publicKey  公钥
     * @param privateKey 私钥
     * @return 共享密钥
     */
    public static SecretKey getSecretKey(byte[] publicKey, byte[] privateKey) throws Exception {
        //1.实例化密钥工厂
        KeyFactory keyFactory = KeyFactory.getInstance(DH_KEY);
        //2.初始化公钥材料，产生公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
        PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //3.初始化私钥材料，产生私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //4.实例化DH
        KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
        //5.初始化
        keyAgreement.init(priKey);
        keyAgreement.doPhase(pubKey, true);
        //6.产生共享密钥
        byte[] secret = keyAgreement.generateSecret();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        byte[] digest = messageDigest.digest(secret);
        return new SecretKeySpec(digest, CIPHER_KEY);
    }


    /**
     * 利用协商密钥进行加密
     *
     * @param data 待加密数据
     * @param secretKey  密钥
     * @return 加密数据
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, SecretKey secretKey) throws Exception {
        //1.数据加密
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }


    /**
     * 解密
     *
     * @param data 待解密数据
     * @param secretKey  密钥
     * @return 解密数据
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(data);
    }

    public static void main(String[] args) throws Exception {
        KeyPair keyPair = generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        SecretKey secretKey = getSecretKey(aPublic.getEncoded(), aPrivate.getEncoded());
        System.out.println(secretKey.getEncoded().length * 8);
        String message = "年后大数据打开啊";
        byte[] encrypt = encrypt(message.getBytes(StandardCharsets.UTF_8), secretKey);
        System.out.println(encrypt.length * 8);
        byte[] decrypt = decrypt(encrypt, secretKey);
        System.out.println(new String(decrypt));
    }
}
