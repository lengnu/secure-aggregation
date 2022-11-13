package com.duwei.protocol;

import lombok.Data;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:11
 * @description 数据包
 */
@Data
public abstract class Packet {
    /**
     * 协议版本
     */
    protected byte version = 1;

    protected abstract byte getMessageType();
}
