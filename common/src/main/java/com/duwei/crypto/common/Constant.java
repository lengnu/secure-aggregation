package com.duwei.crypto.common;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: com.duwei.crypto.common
 * @Author: duwei
 * @Date: 2022/11/10 9:18
 * @Description: 定义参数常量
 */
public interface Constant {
    //int AES_LENGTH = 128;
    int DH_KEY_BIT_LENGTH = 512;
    int AES_KEY_BIT_LENGTH = 256;
    String AES_CIPHER_MODE = "AES";

    /**
     * Shamir秘密共享的有限域大小-bit长度
     */
    int SECRET_SHARE_BIT_LENGTH = 512;

    /**
     * 聚合模数，64位的最大值
     */
    long AGGREGATION_MOD = Long.MAX_VALUE;
}
