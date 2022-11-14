package com.duwei.crypto.shamir;

import com.duwei.crypto.common.Constant;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * @BelongsProject: Secure_Aggregation
 * @BelongsPackage: com.duwei.crypto
 * @Author: duwei
 * @Date: 2022/4/28 16:37
 * @Description: Shamir秘密共享方法
 */
public class SecretShare {
    private static final int BIT_LENGTH = Constant.SECRET_SHARE_BIT_LENGTH;
    private static final Random RANDOM = new Random();
    private static final BigInteger MOD = BigInteger.probablePrime(BIT_LENGTH, RANDOM);


    /**
     * Shamir秘密分享算法
     *
     * @param secret      秘密值
     * @param totalNumber 份额总数
     * @param threshold   恢复阈值
     * @param usersId     每个用户的ID，作为多项式的输入
     * @return Map，key为用户的Id，值为该用户的份额
     */
    public static Map<BigInteger, BigInteger> share(BigInteger secret, int totalNumber, int threshold, BigInteger[] usersId) {
        if (secret == null || threshold > totalNumber
                || threshold < 2 || usersId == null || usersId.length != totalNumber) {
            throw new RuntimeException("输入参数不正确");
        }

        //储存t - 1次多项系系数
        BigInteger[] coefficients = new BigInteger[threshold];
        coefficients[0] = secret;
        for (int i = 1; i < threshold; i++) {
            coefficients[i] = generateRandomBigIntegerLessMod();
        }

        //进行秘密分享
        Map<BigInteger, BigInteger> sharesMap = new HashMap<>();
        for (int i = 0; i < totalNumber; i++) {
            sharesMap.put(usersId[i], computeShare(coefficients, usersId[i]));

        }
        return sharesMap;
    }


    /**
     * 生成小于mod的随机数
     *
     * @return 随机数
     */
    private static BigInteger generateRandomBigIntegerLessMod() {
        return new BigInteger(BIT_LENGTH, RANDOM).mod(MOD);
    }

    /**
     * 根据输入在秘密共享多项式上计算份额
     *
     * @param coefficients 秘密共享多项式
     * @param input        输入
     * @return 生成份额
     */
    private static BigInteger computeShare(BigInteger[] coefficients, BigInteger input) {
        if (coefficients == null || coefficients.length < 2) {
            throw new RuntimeException("系数多项系格式错误");
        }
        int len = coefficients.length;
        BigInteger base = BigInteger.ONE;
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < len; i++) {
            BigInteger cur = coefficients[i].multiply(base);
            base = base.multiply(input);
            result = result.add(cur).mod(MOD);
        }
        return result;
    }


    /**
     * 秘密重建算法
     *
     * @param sharesMap 用户id - 秘密份额
     * @param t         需要恢复的阈值
     * @return 重建的秘密
     * @throws Exception
     */
    public static BigInteger reconstruction(Map<BigInteger, BigInteger> sharesMap, int t) {
        int selected = sharesMap.size();
        if (selected < t) {
            throw new RuntimeException("当前收集的秘密份额不足以恢复秘密");
        }

        BigInteger result = BigInteger.ZERO;
        BigInteger[] userIds = sharesMap.keySet().stream().limit(t).toArray(BigInteger[]::new);
        for (int i = 0; i < t; i++) {
            BigInteger temp = sharesMap.get(userIds[i]).multiply(interpolation(userIds, userIds[i], t));
            result = result.add(temp).mod(MOD);
        }

        return result;
    }

    /**
     * 求解插值多项系
     *
     * @param usersId 所有的用户ID，不能重复
     * @param curId   当前用户ID，必须在curId中
     * @param t       阈值
     * @return 在当前ID上的插值多项式
     */
    public static BigInteger interpolation(BigInteger[] usersId, BigInteger curId, int t) {
        BigInteger result = BigInteger.ONE;
        //常量0，计算f(0)
        BigInteger zero = BigInteger.ZERO;
        for (int i = 0; i < t; i++) {
            //i != j
            if (curId.equals(usersId[i])) {
                continue;
            }

            BigInteger up = zero.subtract(usersId[i]);
            BigInteger down = curId.subtract(usersId[i]);
            BigInteger cur = up.multiply(down.modInverse(MOD));
            result = result.multiply(cur);
        }
        return result.mod(MOD);
    }

    public static void main(String[] args) throws Exception {
        BigInteger[] usersId = new BigInteger[]{
                new BigInteger("12332442"),
                new BigInteger("23424234"),
                new BigInteger("3324324"),
                new BigInteger("4324234"),
                new BigInteger("5423423"),
                new BigInteger("542323423"),
                new BigInteger("5443423"),
        };
        BigInteger secret = new BigInteger("2343423423423424390768644243244324322");
        System.out.println("secret ：\t\t\t" + secret);
        Map<BigInteger, BigInteger> sharesMap = share(secret, usersId.length, 5, usersId);
        BigInteger reconstruction = reconstruction(sharesMap, 5);
        System.out.println("reconstruction ：\t"  + reconstruction);
    }
}


