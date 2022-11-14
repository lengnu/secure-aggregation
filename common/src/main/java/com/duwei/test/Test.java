package com.duwei.test;

import com.duwei.crypto.random.PRG;
import com.duwei.crypto.shamir.SecretShare;

import java.awt.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.List;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.test
 * @Author: duwei
 * @Date: 2022/11/14 15:24
 * @Description: 测试
 */
public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        long advertiseKeysStartTime = 0;
        long advertiseKeysEndTime = 0;
        long advertiseKeysTotalTimes = 0;

        long shareKeysStartTime = 0;
        long shareKeysEndTime = 0;
        long shareKeysTotalTime = 0;

        long maskInputCollectionStartTime = 0;
        long maskInputCollectionEndTime = 0;
        long maskInputCollectionTotalTime = 0;
        //数据维度
        final int dimension = 3;
        //仿真次数
        final int times = 10;
        //总用户数
        final int totalClient = 3;
        //秘密共享阈值
        final int threshold = 2;
        //服务器存储所有用户的公钥
        Map<BigInteger, byte[]> allClientPublicKeyForSessionKey = new HashMap<>();
        Map<BigInteger, byte[]> allClientPublicKeyForPairMaskRandomSeed = new HashMap<>();
        Map<BigInteger, long[]> clientSubmitMaskInputMap = new HashMap<>();
        //用户的ID
        int nextId = 0;
        Map<BigInteger, Client> userIdMap = new HashMap<>();
        //所有提交了公钥的用户Id- U1
        List<BigInteger> registerPublicKeyUserList = new ArrayList<>();
        //分享了自己的用户Id - U2
        List<BigInteger> shareKeyUserList = new ArrayList<>();
        //先服务器提交了本地梯度的用户Id - U3
        List<BigInteger> submitLocalModelUserList = new ArrayList<>();


        // key：    formClientId
        // value：
        //      key:toClientId
        //      value：秘密分享的信息
        Map<BigInteger, Map<BigInteger, Client.ShareKeyInformation>> allClientShareKeyMap = new HashMap<>();

        for (int i = 0; i < 1; i++) {
            //1.AdvertiseKeys
            //1.1   所有用于提交公钥到服务器
            advertiseKeysStartTime = System.currentTimeMillis();
            for (int j = 0; j < totalClient; j++) {
                Client client = new Client();
                client.initKey();
                BigInteger curClientId = BigInteger.valueOf(++nextId);
                client.setId(curClientId);
                userIdMap.put(client.getId(), client);
                registerPublicKeyUserList.add(client.getId());
                //服务器记录各个客户端的公钥信息
                allClientPublicKeyForSessionKey.put(client.getId(), client.getLocalPublicKeyToSessionKey());
                allClientPublicKeyForPairMaskRandomSeed.put(client.getId(), client.getLocalPublicKeyToPairMaskRandomSeed());
            }
            //1.2   服务器向各个用户转发其他用户的公钥信息
            registerPublicKeyUserList.forEach(clientId -> {
                Client curClient = userIdMap.get(clientId);
                curClient.setOtherClientPublicKeyToPairRandomSeed(allClientPublicKeyForPairMaskRandomSeed);
                curClient.setOtherClientPublicKeyToSessionKey(allClientPublicKeyForSessionKey);
                curClient.setRegisterPublicKeyClientList(registerPublicKeyUserList);
                curClient.setTotalClient(totalClient);
                curClient.setThreshold(threshold);
            });
            advertiseKeysEndTime = System.currentTimeMillis();
            advertiseKeysTotalTimes += (advertiseKeysEndTime - advertiseKeysStartTime);


            //2.ShareKeys - 客户端生成double mask并把其和自己用来生成随机种子的私钥进行秘密共享
            shareKeysStartTime = System.currentTimeMillis();
            registerPublicKeyUserList.stream().
                    filter((clientId) -> true).
                    forEach(clientId -> {
                        Client curClient = userIdMap.get(clientId);
                        //2.1   客户端生成double Mask
                        curClient.generateDoubleMaskRandomSeed();
                        //2.2   生成double Mask和私钥的份额
                        curClient.secretShare();
                        //2.3   密钥协商出会话密钥
                        curClient.keyAgreementGenerateSessionKey();
                        //2.4   用协商出来的会话密钥加密发给服务器，由服务器进行转发
                        curClient.dispatchShare();
                        //2.5   服务器收集对应的份额
                        allClientShareKeyMap.put(clientId, curClient.getMessageDispatchShareKeyMap());
                        //2.6 将当前用户添加到U2集合里面
                        shareKeyUserList.add(clientId);
                    });
            //2.7       服务器转发对应的份额到各个客户端
            shareKeyUserList.forEach((fromClientId) -> {
                Map<BigInteger, Client.ShareKeyInformation> curClientShareKeyInformation = allClientShareKeyMap.get(fromClientId);
                curClientShareKeyInformation.forEach((toClientId, information) -> {
                    Client toClient = userIdMap.get(toClientId);
                    toClient.addOtherClientOneShareInformationRecord(fromClientId, information);
                    toClient.setShareKeyClientList(shareKeyUserList);
                });
            });
            shareKeysEndTime = System.currentTimeMillis();
            shareKeysTotalTime = shareKeysStartTime - shareKeysEndTime;


            //3.客户端掩盖自己的输入，服务器收集客户端信息
            //3.1   客户端解密服务器的消息，TODO 这部没有加密，先省略
            //3.2   客户端与那些发送了秘密份额的用户生成随机掩码
            //3.3   客户端掩盖自己的输入并上传服务器端
            maskInputCollectionStartTime = System.currentTimeMillis();
            shareKeyUserList.stream()
                    .filter((clientId) -> true)
                    .forEach(clientId -> {
                        Client curClient = userIdMap.get(clientId);
                        curClient.keyAgreementGeneratePairMaskRandomSeed();
                        curClient.maskInput();
                        submitLocalModelUserList.add(clientId);
                        clientSubmitMaskInputMap.put(clientId, curClient.getMaskInput());
                    });
            maskInputCollectionEndTime = System.currentTimeMillis();
            maskInputCollectionTotalTime = maskInputCollectionEndTime - maskInputCollectionStartTime;


            //4.服务器消除掩码，对于在线的用于请求b，离线的用户请求u
            //4.1   恢复掩码
            Map<BigInteger, byte[]> onlineClientDoubleMaskRandomSeed = new HashMap<>();
            Map<BigInteger,int[]> onlineClientDoubleMaskSequences = new HashMap<>();
            allClientShareKeyMap.forEach((formClientId, toClientInformationMap) -> {
                Map<BigInteger, byte[]> sharesMap = new HashMap<>();
                toClientInformationMap.forEach((toClientId, information) -> {
                    sharesMap.put(toClientId, information.getShareDoubleMashRandomSeed());
                });
                byte[] reconstruction = SecretShare.reconstruction(sharesMap, threshold);
                onlineClientDoubleMaskRandomSeed.put(formClientId,reconstruction);
                onlineClientDoubleMaskSequences.put(formClientId, PRG.pseudoRandomSequencesInt(dimension,reconstruction));
            });
            //4.2   消除掩码
            long[] aggregationResult = new long[dimension];
            for (int j = 0; j < dimension; j++) {
                aggregationResult[j] = 0;
                //先聚合所有的maskInput
                for (Map.Entry<BigInteger,long[]> entry : clientSubmitMaskInputMap.entrySet()){
                    BigInteger clientId = entry.getKey();
                    long[] maskInput = entry.getValue();
                    //聚合输入
                    aggregationResult[j] += maskInput[j];
                    //消除掩码
                    aggregationResult[j] -= onlineClientDoubleMaskSequences.get(clientId)[j];
                }
            }
            System.out.println("aggregation = " + Arrays.toString(aggregationResult));

            long[] originAgg = new long[dimension];
            for (int j = 0; j < dimension; j++) {
                for (Map.Entry<BigInteger,Client> entry : userIdMap.entrySet()){
                    Client client = entry.getValue();
                    originAgg[j] += client.getInput()[j];
                }
            }
            System.out.println("origin Aggregation = " + Arrays.toString(originAgg));

        }


    }
}
