package com.duwei.crypto.aggrement;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.aggrement
 * @Author: duwei
 * @Date: 2022/11/14 9:13
 * @Description: ECDH密钥交换算法, 基于NIST P-256椭圆曲线
 */
public class ECDH {
    /**
     * 采用NIST P-256生成椭圆曲线
     */
    private static final String KEY_GENERATE_ALGORITHM = "EC";
    /**
     * 256位长度
     */
    private static final int KEY_LENGTH = 256;
    /**
     * ECDH密钥交换算法
     */
    private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

    /**
     * 根据算法和长度生成密钥对
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_GENERATE_ALGORITHM);
        //设置密钥长度
        keyPairGenerator.initialize(KEY_LENGTH);
        return keyPairGenerator.generateKeyPair();
    }

    public static SecretKey keyAgreementGenerateAES128SecretKey(byte[] publicKeyByte,byte[] privateKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        byte[] bytes = keyAgreement(publicKeyByte, privateKeyByte);
        return new SecretKeySpec(bytes,0,16,"AES");
    }

    public static SecretKey keyAgreementGenerateAES256SecretKey(byte[] publicKeyByte,byte[] privateKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        byte[] bytes = keyAgreement(publicKeyByte, privateKeyByte);
        return new SecretKeySpec(bytes,0,32,"AES");
    }

    public static byte[] keyAgreementRandomSeed(byte[] publicKeyByte,byte[] privateKeyByte) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        return keyAgreement(publicKeyByte, privateKeyByte);
    }




    private static byte[] keyAgreement(byte[] publicKeyByte,byte[] privateByte) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        //1.转换密钥
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_GENERATE_ALGORITHM);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateByte);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyByte);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

        //2.密钥协商
        KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey,true);
        return keyAgreement.generateSecret();
    }



    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        KeyPair keyPair = generateKeyPair();
        PublicKey aPublic = keyPair.getPublic();
        PrivateKey aPrivate = keyPair.getPrivate();
        byte[] bytes = keyAgreement(aPublic.getEncoded(), aPrivate.getEncoded());
        System.out.println(bytes.length * 8);
        System.out.println(new SecretKeySpec(bytes,0,16,"AES"));
    }
}
