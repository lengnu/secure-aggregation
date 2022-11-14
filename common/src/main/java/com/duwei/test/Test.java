package com.duwei.test;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.test
 * @Author: duwei
 * @Date: 2022/11/14 15:24
 * @Description: 测试
 */
public class Test {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        //仿真次数
        final int times = 100;
        //总用户数
        final int totalClient = 100;
        //秘密共享阈值
        final int threshold = 60;
        //服务器存储所有用户的公钥
        Map<BigInteger,byte[]> allUserPublicKeyForEnc = new HashMap<>();
        Map<BigInteger,byte[]> allUserPublicKeyForDH = new HashMap<>();
        //用户的ID
        int nextId = 0;
        Map<BigInteger,Client> userIdMap = new HashMap<>();

        //1.所有提交了公钥的用户ID - U1
        List<BigInteger> registerPublicKeyUserList = new ArrayList<>();


        for (int i = 0; i < 1; i++) {
            //1.所有用于提交公钥到服务器
            for (int j = 0; j < totalClient; j++) {
                Client client = new Client();
                BigInteger curClientId = BigInteger.valueOf(++nextId);
                client.setId(curClientId);
                userIdMap.put(client.getId(),client);
                registerPublicKeyUserList.add(client.getId());

                //记录各个用户的公钥信息
                allUserPublicKeyForEnc.put(client.getId(),client.getPublicKeyForEncrypt());
                allUserPublicKeyForDH.put(client.getId(),client.getPublicKeyForPairMaskRandomSeed());
            }


            //2.服务器向各个用户转发其他用户的公钥信息
            registerPublicKeyUserList.forEach( clientId -> {
                Client curClient = userIdMap.get(clientId);
                curClient.setPublicKeyForPairMaskRandomSeedMap(allUserPublicKeyForDH);
                curClient.setRegisterPublicKeyUserList(registerPublicKeyUserList);
                curClient.setPublicKeyForEncryptMap(allUserPublicKeyForEnc);
                curClient.setTotalClient(totalClient);
                curClient.setThreshold(threshold);
            });


            //3.各个客户端对自己的数据进行秘密共享并采用协商密钥转发
            registerPublicKeyUserList.forEach(clientId -> {
                Client curClient = userIdMap.get(clientId);
                //对自己的私钥和b进行秘密共享
                curClient.keyAgreement();
            } );

            registerPublicKeyUserList.forEach(clientId -> {
                System.out.println("client id : " + clientId);
                Client client = userIdMap.get(clientId);
                Map<BigInteger, byte[]> keyAgreeForEncrypt = client.getKeyAgreeForEncrypt();
                keyAgreeForEncrypt.forEach((key,value) -> System.out.println("client keyAgreement id" + key + " result : " + Arrays.toString(value)));

            });
        }




    }
}
