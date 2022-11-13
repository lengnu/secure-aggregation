package com.duwei.protocol.response;

import com.duwei.protocol.Packet;
import lombok.Data;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:16
 * @description 注册公钥响应
 */
@Data
public class RegisterPublicKeyResponsePacket extends Packet {
    /**
     * 用户ID的列表
     */
    private List<Integer> userIdList;
    /**
     * 用于ID - publicKey的映射（用来协商加密的公钥）
     */
    private Map<Integer,byte[]> allUserIdPublicKeyForEncMap;
    /**
     * 用于ID - publicKey的映射（用来协商随机数的公钥）
     */
    private Map<Integer,byte[]> allUserIdPublicKeyForPRGMap;

    @Override
    protected byte getMessageType() {
        return 0;
    }
}
