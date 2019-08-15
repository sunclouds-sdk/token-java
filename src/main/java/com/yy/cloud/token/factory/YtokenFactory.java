package com.yy.cloud.token.factory;

import com.yy.cloud.token.Ytoken;

import java.util.Map;

public class YtokenFactory {

    private static YtokenFactory ytokenFactory = new YtokenFactory();

    public static YtokenFactory getInstance() {

        if (ytokenFactory == null) {
            synchronized (YtokenFactory.class) {
                if (ytokenFactory == null) {
                    ytokenFactory = new YtokenFactory();
                }
            }
        }
        return ytokenFactory;
    }

    private YtokenFactory() {

    }

    public String createToken(int appKey, String vuid, String appSecret) {
        return new Ytoken().buildToken(appKey, vuid).convertToString(appSecret);
    }

    public String createToken(int appKey, String vuid, int validTime, String appkey) {
        return new Ytoken().buildToken(appKey, vuid, validTime).convertToString(appkey);
    }

    public String createToken(int appKey, String vuid, int validTime, Map<String, String> parameterMap, Map<String, Long> privilegesMap, String appSecret) {
        return new Ytoken().buildToken(appKey, vuid, validTime, parameterMap, privilegesMap).convertToString(appSecret);
    }

    public Ytoken convertFromString(int appKey, String appSecret, String token) {
        return new Ytoken().convertFromString(appKey, appSecret, token);
    }

}