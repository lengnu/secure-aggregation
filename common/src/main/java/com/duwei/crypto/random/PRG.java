package com.duwei.crypto.random;

import java.lang.reflect.Field;
import java.security.SecureRandom;
import java.util.stream.IntStream;


/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.prg
 * @Author: duwei
 * @Date: 2022/11/14 11:16
 * @Description: 伪随机数生成器
 */
public class PRG {
    /**
     * 根据随机种子生成指定长度的随机序列，随机序列都是int类型
     * @param length
     * @param seed
     * @return
     */
    public static int[]  pseudoRandomSequencesInt(int length,byte[] seed){
        SecureRandom secureRandom = new SecureRandom(seed);
        return secureRandom.ints().limit(length).toArray();
    }

    /**
     * 根据随机种子生成指定长度的随机序列，随机序列都是long类型
     * @param length
     * @param seed
     * @return
     */
    public static long[] pseudoRandomSequencesLong(int length,byte[] seed){
        SecureRandom secureRandom = new SecureRandom(seed);
        return secureRandom.longs().limit(length).toArray();
    }

    public static void main(String[] args) throws NoSuchFieldException, IllegalAccessException {
        SecureRandom secureRandom = new SecureRandom();
        byte[] arr = new byte[2];
        secureRandom.nextBytes(arr);
        IntStream ints = secureRandom.ints(20);
        Class<? extends SecureRandom> aClass = secureRandom.getClass();
        Field counter = aClass.getDeclaredField("counter");
        counter.setAccessible(true);
        System.out.println(counter.get(secureRandom));
    }

}
