package com.duwei.protocol.request;

import com.duwei.protocol.Packet;
import com.duwei.protocol.message.MessageType;
import lombok.Data;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:15
 * @description 注册公钥请求
 */
@Data
public class RegisterPublicKeyRequestPacket extends Packet {
    /**
     * 用来协商加密的公钥
     */
    private byte[] publicKeyForEnc;
    /**
     * 用来协商随机种子的公钥
     */
    private byte[] publicKeyForPRG;

    @Override
    protected byte getMessageType() {
        return MessageType.REGISTER_PUBLIC_KEY_REQUEST;
    }
}
