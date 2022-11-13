package com.duwei.protocol;

import com.duwei.protocol.message.MessageType;
import com.duwei.protocol.request.RegisterPublicKeyRequestPacket;
import com.duwei.protocol.response.RegisterPublicKeyResponsePacket;
import com.duwei.protocol.serialize.Serializer;
import com.duwei.protocol.serialize.impl.JsonSerializer;
import io.netty.buffer.ByteBuf;

import java.util.HashMap;
import java.util.Map;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:36
 * @description 消息编码器，按照自定义协议封装消息
 */
public class PacketCodec {
    /**
     * 魔数
     */
    public static final int MAGIC_NUMBER = 0x12345678;
    public static final PacketCodec INSTANCE = new PacketCodec();

    private static final Map<Byte, Class<? extends Packet>> packetTypeMap;
    private static final Serializer serialize = JsonSerializer.INSTANCE;

    static {
        packetTypeMap = new HashMap<>();
        packetTypeMap.put(MessageType.REGISTER_PUBLIC_KEY_REQUEST, RegisterPublicKeyRequestPacket.class);
        packetTypeMap.put(MessageType.REGISTER_PUBLIC_KEY_RESPONSE, RegisterPublicKeyResponsePacket.class);
    }


    /**
     * 消息编码
     *
     * @param byteBuf 编码后写入到byteBuf中
     * @param packet  消息包
     */
    public void encode(ByteBuf byteBuf, Packet packet) {
        //1.写入魔数
        byteBuf.writeInt(MAGIC_NUMBER);

        //2.写入版本号
        byteBuf.writeByte(packet.getVersion());

        //3.写入序列化算法
        byteBuf.writeByte(serialize.getSerializerAlgorithm());

        //4.写入消息类型
        byteBuf.writeByte(packet.getMessageType());

        //5.写入数据长度
        byte[] bytes = serialize.serialize(packet);
        byteBuf.writeInt(bytes.length);

        //6.写入实际数据
        byteBuf.writeBytes(bytes);
    }


    /**
     * 解码器，将ByteBuf变为对应的Packet
     *
     * @param byteBuf
     * @return
     */
    public Packet decode(ByteBuf byteBuf) {
        //1.跳过魔数
        byteBuf.skipBytes(4);

        //2.跳过版本
        byteBuf.skipBytes(1);

        //3.拿到序列化算法
        byte serializeAlgorithm = byteBuf.readByte();

        //4.拿到消息类型
        byte messageType = byteBuf.readByte();

        //5.消息长度
        int length = byteBuf.readInt();

        //6.读取实际消息
        byte[] bytes = new byte[length];
        byteBuf.readBytes(bytes);

        Class<? extends Packet> requestType = getRequestType(messageType);

        //有对应的消息类型和序列化器
        if (requestType != null && serialize != null) {
            return serialize.deserializer(requestType, bytes);
        }
        return null;
    }


    private Class<? extends Packet> getRequestType(byte messageType) {
        return packetTypeMap.get(messageType);
    }
}
