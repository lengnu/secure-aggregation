package com.duwei.entity;

import lombok.Data;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 13:04
 * @description client的实体类
 */
@Data
public class User {
    private int id;
    private byte[] publicKeyForEnc;
    private byte[] publicKeyForPRG;

    public User(byte[] publicKeyForEnc, byte[] publicKeyForPRG) {
        this.publicKeyForEnc = publicKeyForEnc;
        this.publicKeyForPRG = publicKeyForPRG;
    }
}
