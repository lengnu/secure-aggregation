package com.duwei.protocol.message;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:12
 * @description 消息类型
 */
public interface MessageType {
    /**
     * 各个客户端在服务器注册公钥请求
     */
    byte REGISTER_PUBLIC_KEY_REQUEST = 1;
    /**
     * 各个客户端在服务器注册公钥响应
     */
    byte REGISTER_PUBLIC_KEY_RESPONSE = 2;

}
