package com.duwei.protocol.serialize.impl;

import com.alibaba.fastjson.JSON;
import com.duwei.protocol.serialize.Serializer;
import com.duwei.protocol.serialize.SerializerAlgorithm;

/**
 * @BelongsProject: distribute-store-code
 * @BelongsPackage: com.distribute.store.code.serialize.impl
 * @Author: duwei
 * @Date: 2022/7/12 17:27
 * @Description: JSON序列化实现类
 */
public class JsonSerializer implements Serializer {
    public static final JsonSerializer INSTANCE = new JsonSerializer();

    private JsonSerializer() {

    }

    @Override
    public byte getSerializerAlgorithm() {
        return SerializerAlgorithm.JSON;
    }

    @Override
    public byte[] serialize(Object object) {
        return JSON.toJSONBytes(object);
    }

    @Override
    public <T> T deserializer(Class<T> clazz, byte[] data) {
        return JSON.parseObject(data, clazz);
    }
}
