package com.duwei.handler;

import com.duwei.entity.User;
import com.duwei.parameter.PublicParameters;
import com.duwei.protocol.request.RegisterPublicKeyRequestPacket;
import com.duwei.session.SessionUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;

/**
 * @author duwei
 * @version 1.0.0
 * @create 2022-11-11 12:59
 * @description 处理客户端的注册公钥请求
 */
public class RegisterPublicKeyRequestHandler extends SimpleChannelInboundHandler<RegisterPublicKeyRequestPacket> {
    @Override
    protected void channelRead0(ChannelHandlerContext ctx, RegisterPublicKeyRequestPacket request) throws Exception {
        byte[] publicKeyForEnc = request.getPublicKeyForEnc();
        byte[] publicKeyForPRG = request.getPublicKeyForPRG();
        User user = new User(publicKeyForEnc,publicKeyForPRG);
        SessionUtil.sessionBind(user, ctx.channel());
        //判断一下注册的用户数量是否达到
        if (SessionUtil.getRegisterPublicKeyNumber() == PublicParameters.totalClientNumber){
            ctx.executor().submit(() -> {

            });
        }



    }
}
