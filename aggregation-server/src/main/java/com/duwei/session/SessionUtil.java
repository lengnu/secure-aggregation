package com.duwei.session;

import com.duwei.entity.User;
import io.netty.channel.Channel;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 13:02
 * @description 存储在线用户列表
 */
public class SessionUtil {
    private static AtomicInteger globalUserId = new AtomicInteger(0);
    private static Map<Integer, User> userIdInformationMap = new HashMap<>();
    private static Map<Integer, Channel> userIdChannelMap = new HashMap<>();
    private static List<Integer> registerPublicKeyUserList = new ArrayList<>();
    private static List<Integer> shareSecretUserList = new ArrayList<>();
    private static List<Integer> uploadModelUserList = new ArrayList<>();

    synchronized public static int sessionBind(User user,Channel channel) {
        int userId = globalUserId.incrementAndGet();
        user.setId(userId);
        userIdChannelMap.put(userId,channel);
        userIdInformationMap.put(userId,user);
        registerPublicKeyUserList.add(userId);
        return userId;
    }

    /**
     * 得到当前注册了公钥的用户数量
     * @return
     */
     public static int getRegisterPublicKeyNumber(){
        return registerPublicKeyUserList.size();
    }
}
