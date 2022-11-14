package com.duwei.test;

import com.duwei.crypto.aggrement.ECDH;
import com.duwei.crypto.shamir.SecretShare;
import lombok.Data;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.test
 * @Author: duwei
 * @Date: 2022/11/14 15:15
 * @Description: 测试客户端
 */
@Data
public class Client {
    private BigInteger id;
    //本地用户的公钥
    private byte[] publicKeyForEncrypt;
    private byte[] publicKeyForPairMaskRandomSeed;

    //本地用户的私钥
    private byte[] privateKeyForEncrypt;
    private byte[] privateKeyForPairMaskRandomSeed;

    //存储不同用户的公钥
    private Map<BigInteger, byte[]> publicKeyForEncryptMap;
    private Map<BigInteger, byte[]> publicKeyForPairMaskRandomSeedMap;

    //存储秘密共享的份额
    private Map<BigInteger, BigInteger> pairMaskRandomSeedShareMap;
    private Map<BigInteger, BigInteger> doubleMaskRandomSeedShareMap;

    //第二层掩码种子
    private byte[] doubleMaskRandomSeed;
    private int doubleMaskRandomSeedLength = 128;

    //用户的秘密值
    private int[] input;

    //注册了公钥的用户列表
    private List<BigInteger> registerPublicKeyUserList;

    private int totalClient;
    private int threshold;

    //协商出来用于加密的密钥
    private Map<BigInteger, byte[]> keyAgreeForEncrypt = new HashMap<>();
    //协商出来的随机种子
    private Map<BigInteger, byte[]> keyAgreeForPairMaskRandomSeed = new HashMap<>();

    public Client() throws NoSuchAlgorithmException {
        initKey();
    }

    public void initKey() throws NoSuchAlgorithmException {
        KeyPair keyPairForEncrypt = ECDH.generateKeyPair();
        KeyPair keyPairForRandomSeed = ECDH.generateKeyPair();
        //用于加密的DH公私钥
        this.publicKeyForEncrypt = keyPairForEncrypt.getPublic().getEncoded();
        this.privateKeyForEncrypt = keyPairForEncrypt.getPrivate().getEncoded();

        //用于产生随机种子的DH公私钥
        this.publicKeyForPairMaskRandomSeed = keyPairForRandomSeed.getPublic().getEncoded();
        this.privateKeyForPairMaskRandomSeed = keyPairForRandomSeed.getPrivate().getEncoded();

        //生成自己的本地随机doubleMask
        this.doubleMaskRandomSeed = new byte[doubleMaskRandomSeedLength];
        new SecureRandom().nextBytes(doubleMaskRandomSeed);
    }

    //对自己的种子DH私钥和随机数b进行秘密共享
    public void secretShare() {
        //分享自己的DH私钥用于生成随机数的
        Map<BigInteger, BigInteger> sharesForPairMaskPrivateKey =
                SecretShare.share(new BigInteger(privateKeyForPairMaskRandomSeed), totalClient, threshold, registerPublicKeyUserList.toArray(new BigInteger[0]));
        this.pairMaskRandomSeedShareMap = sharesForPairMaskPrivateKey;

        Map<BigInteger, BigInteger> sharesForDoubleMaskRandomSeed =
                SecretShare.share(new BigInteger(this.doubleMaskRandomSeed), totalClient, threshold, registerPublicKeyUserList.toArray(new BigInteger[0]));
        this.doubleMaskRandomSeedShareMap = sharesForDoubleMaskRandomSeed;
    }


    //密钥协商出成对掩码的种子和会话密钥
    public void keyAgreement() {
        registerPublicKeyUserList.stream().filter( clientId -> !clientId.equals(this.id)).forEach(clientId -> {
            try {
                //1.对方用户的公钥,协商用于加密的会话密钥
                byte[] counterpartPublicKeyForEncrypt = publicKeyForEncryptMap.get(clientId);
                SecretKey secretKey = ECDH.keyAgreementGenerateAES256SecretKey(counterpartPublicKeyForEncrypt, privateKeyForEncrypt);
                keyAgreeForEncrypt.put(clientId, secretKey.getEncoded());

                //2.协商出成对掩码的随机种子
                byte[] counterpartPublicKeyForPairMaskRandomSeed = publicKeyForPairMaskRandomSeedMap.get(clientId);
                byte[] pairMaskRandomSeed = ECDH.keyAgreementRandomSeed(counterpartPublicKeyForPairMaskRandomSeed, privateKeyForPairMaskRandomSeed);
                keyAgreeForPairMaskRandomSeed.put(clientId, pairMaskRandomSeed);
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

}
