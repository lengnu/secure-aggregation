package com.duwei.protocol.serialize;

/**
 * @BelongsProject: distribute-store-code
 * @BelongsPackage: com.distribute.store.code.serialize
 * @Author: duwei
 * @Date: 2022/7/12 17:25
 * @Description: 序列化接口
 */
public interface Serializer {
    /**
     * 序列化算法
     * @return
     */
    byte getSerializerAlgorithm();

    /**
     * 将Java对象序列化为二进制
     * @param object    Java对象
     * @return          字节数组
     */
    byte[] serialize(Object object);

    /**
     * 将字节数组反序列化为Java对象
     * @param clazz 反序列化的类型
     * @param data  字节数组
     * @param <T>
     * @return
     */
    <T> T deserializer(Class<T> clazz,byte[] data);
}
