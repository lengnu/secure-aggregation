package com.duwei.crypto.random;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.random
 * @Author: duwei
 * @Date: 2022/11/10 16:44
 * @Description: 伪随机数生成器
 */
public class PRG extends Random {

    public PRG(long seed) {
        super(seed);
    }

    /**
     * 生成指定数量的随机数,范围是int类型
     *
     * @param number 伪随机序列的长度
     * @return 伪随机序列
     */
    public int[] pseudoRandomSequencesInt(int number) {
        int[] result = new int[number];
        for (int i = 0; i < number; i++) {
            result[i] = super.nextInt();
        }
        return result;
    }

}
