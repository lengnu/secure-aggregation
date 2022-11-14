package com.duwei.test;

import com.duwei.crypto.aggrement.ECDH;
import com.duwei.crypto.random.PRG;
import com.duwei.crypto.shamir.SecretShare;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.test
 * @Author: duwei
 * @Date: 2022/11/14 15:15
 * @Description: 测试客户端
 */
@Data
public class Client {
    /**
     * 客户端ID
     */
    private BigInteger id;
    /**
     * 客户端的本地公钥
     */
    private byte[] localPublicKeyToSessionKey;
    private byte[] localPublicKeyToPairMaskRandomSeed;

    /**
     * 客户端的本地私钥
     */
    private byte[] localPrivateToSessionKey;
    private byte[] localPrivateKeyToPairMaskRandomSeed;

    /**
     * 系统中其它用户的公钥
     */
    private Map<BigInteger, byte[]> otherClientPublicKeyToSessionKey;
    private Map<BigInteger, byte[]> otherClientPublicKeyToPairRandomSeed;

    /**
     * 存储本地需要分享给其它客户端秘密共享的份额
     */
    private Map<BigInteger, byte[]> localPairMaskRandomSeedShareMap;
    private Map<BigInteger, byte[]> localDoubleMaskRandomSeedShareMap;


    /**
     * 本地的double Mask随机种子
     */
    private byte[] doubleMaskRandomSeed;
    private int doubleMaskRandomSeedLength = 64;

    /**
     * 输入向量的维度
     */
    private static final int dimension = 3;
    /**
     * 客户端的私钥输入(32bit以内)
     * 维度为为dimension
     */
    private int[] input = new int[dimension];
    /**
     * 客户端经过掩盖的输入
     */
    private long[] maskInput = new long[dimension];

    /**
     * 所有在服务器注册了的客户端列表
     */
    private List<BigInteger> registerPublicKeyClientList;
    /**
     * 进行了秘密分享的客户端列表
     */
    private List<BigInteger> shareKeyClientList;

    /**
     * 总的客户端数量
     */
    private int totalClient;
    /**
     * 秘密共享阈值
     */
    private int threshold;

    /**
     * 协商出来用于加密的会话密钥
     */
    private Map<BigInteger, byte[]> sessionKeyByKeyAgreement = new HashMap<>();
    /**
     * 协商出来用来生成成对掩码的种子
     */
    private Map<BigInteger, byte[]> pairMaskRandomSeedByAgreement = new HashMap<>();
    /**
     * 用于秘密分享的信息
     */
    private ShareKeyInformation shareKeyInformation;

    public Client() {
        //产生自己的私有输入
        Random random = new Random(System.nanoTime());
        for (int i = 0; i < dimension; i++) {
            input[i] = Math.abs(random.nextInt());
        }
    }

    public void initKey() throws NoSuchAlgorithmException {
        KeyPair keyPairForEncrypt = ECDH.generateKeyPair();
        KeyPair keyPairForRandomSeed = ECDH.generateKeyPair();
        //用于加密的DH公私钥
        this.localPublicKeyToSessionKey = keyPairForEncrypt.getPublic().getEncoded();
        this.localPrivateToSessionKey = keyPairForEncrypt.getPrivate().getEncoded();

        //用于产生随机种子的DH公私钥
        this.localPublicKeyToPairMaskRandomSeed = keyPairForRandomSeed.getPublic().getEncoded();
        this.localPrivateKeyToPairMaskRandomSeed = keyPairForRandomSeed.getPrivate().getEncoded();

        //生成自己的本地随机doubleMask
        this.doubleMaskRandomSeed = new byte[doubleMaskRandomSeedLength];
    }

    //客户端生成自己的本地掩码随机种子
    public void generateDoubleMaskRandomSeed() {
        SecureRandom secureRandom = new SecureRandom();
        this.doubleMaskRandomSeed = new byte[doubleMaskRandomSeedLength];
        secureRandom.nextBytes(this.doubleMaskRandomSeed);
    }

    //存储向其它用户的消息转发份额
    private Map<BigInteger, ShareKeyInformation> messageDispatchShareKeyMap = new HashMap<>();

    //存储其它用户向自己的消息份额
    private Map<BigInteger, ShareKeyInformation> otherClientDispatchShareKeyMap = new HashMap<>();

    public void addOtherClientOneShareInformationRecord(BigInteger toClientId, ShareKeyInformation shareKeyInformation) {
        this.otherClientDispatchShareKeyMap.put(toClientId, shareKeyInformation);
    }

    //对自己的种子DH私钥和随机数b进行秘密共享
    public void secretShare() {
        //分享自己的DH私钥用于生成随机数的
        this.localPairMaskRandomSeedShareMap =
                SecretShare.share(new BigInteger(localPrivateKeyToPairMaskRandomSeed), totalClient, threshold, registerPublicKeyClientList.toArray(new BigInteger[0]));
        this.localDoubleMaskRandomSeedShareMap =
                SecretShare.share(new BigInteger(this.doubleMaskRandomSeed), totalClient, threshold, registerPublicKeyClientList.toArray(new BigInteger[0]));
    }

    public void dispatchShare() {
        //TODO 需要对消息进行加密并转发到服务器
        //这里先不进行加密
        this.localPairMaskRandomSeedShareMap.forEach((toClientId, clientShare) -> {
            if (!toClientId.equals(this.id)) {
                //会话密钥
                byte[] sessionKey = sessionKeyByKeyAgreement.get(toClientId);
                ShareKeyInformation shareKeyInformation =
                        new ShareKeyInformation(this.id, toClientId,
                                localPairMaskRandomSeedShareMap.get(toClientId),
                                localDoubleMaskRandomSeedShareMap.get(toClientId));
                //TODO 先不加密
                messageDispatchShareKeyMap.put(toClientId, shareKeyInformation);
            }
        });
    }


    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    static class ShareKeyInformation {
        private BigInteger fromClientId;
        private BigInteger toClientId;
        private byte[] sharePairMaskRandomSeed;
        private byte[] shareDoubleMashRandomSeed;
    }

    //密钥协商出会话密钥
    public void keyAgreementGenerateSessionKey() {
        registerPublicKeyClientList
                .forEach((clientId -> {
                    if (!clientId.equals(this.id)) {
                        try {
                            byte[] counterpartPublicKeyForSessionKey = otherClientPublicKeyToSessionKey.get(clientId);
                            SecretKey secretKey = ECDH.keyAgreementGenerateAES128SecretKey(counterpartPublicKeyForSessionKey, localPrivateToSessionKey);
                            sessionKeyByKeyAgreement.put(clientId, secretKey.getEncoded());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }));
    }


    //密钥协商出成对掩码
    public void keyAgreementGeneratePairMaskRandomSeed() {
        shareKeyClientList
                .forEach((clientId -> {
                    if (!clientId.equals(this.id)) {
                        try {
                            byte[] counterpartPublicKeyForSessionKey = otherClientPublicKeyToPairRandomSeed.get(clientId);
                            byte[] pairMaskRandomSeed = ECDH.keyAgreementRandomSeed(counterpartPublicKeyForSessionKey, localPrivateToSessionKey);
                            pairMaskRandomSeedByAgreement.put(clientId, pairMaskRandomSeed);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }));
    }

    //客户端掩盖自己的私有输入
    public void maskInput() {
        //首先生成所有的成对随机序列
        Map<BigInteger, int[]> localPairMaskRandomSequences = new HashMap<>();
        this.pairMaskRandomSeedByAgreement.forEach((agreementId, pairMaskRandomSeed) -> {
            int[] randomSequencesInt = PRG.pseudoRandomSequencesInt(dimension, pairMaskRandomSeed);
            localPairMaskRandomSequences.put(agreementId, randomSequencesInt);
        });

        //生成本地的double Mask(b)序列
        int[] localDoubleMaskRandomSequences = PRG.pseudoRandomSequencesInt(dimension, doubleMaskRandomSeed);

        //遍历每个维度,开始进行掩盖
        for (int i = 0; i < dimension; i++) {
            long result = input[i];
            for (Map.Entry<BigInteger, int[]> entry : localPairMaskRandomSequences.entrySet()) {
                BigInteger agreementClientId = entry.getKey();
                int[] pairMaskRandomSequences = entry.getValue();
                if (this.id.compareTo(agreementClientId) < 0) {
                    result += pairMaskRandomSequences[i];
                } else {
                    result -= pairMaskRandomSequences[i];
                }
                result += localDoubleMaskRandomSequences[i];
            }
            maskInput[i] = result;
        }
    }

}
