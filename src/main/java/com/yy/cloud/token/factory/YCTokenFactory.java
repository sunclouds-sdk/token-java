package com.yy.cloud.token.factory;

import com.yy.cloud.token.YCToken;

import java.util.Map;

public class YCTokenFactory {

    private static YCTokenFactory YCTokenFactory = new YCTokenFactory();

    public static YCTokenFactory getInstance() {

        if (YCTokenFactory == null) {
            synchronized (YCTokenFactory.class) {
                if (YCTokenFactory == null) {
                    YCTokenFactory = new YCTokenFactory();
                }
            }
        }
        return YCTokenFactory;
    }

    private YCTokenFactory() {

    }

    public String createToken(int appKey, String vuid, String appSecret) {
        return new YCToken().buildToken(appKey, vuid).convertToString(appSecret);
    }

    public String createToken(int appKey, String vuid, int validTime, String appkey) {
        return new YCToken().buildToken(appKey, vuid, validTime).convertToString(appkey);
    }

    public String createToken(int appKey, String vuid, int validTime, Map<String, String> parameterMap, Map<String, Long> privilegesMap, String appSecret) {
        return new YCToken().buildToken(appKey, vuid, validTime, parameterMap, privilegesMap).convertToString(appSecret);
    }

    public YCToken convertFromString(int appKey, String appSecret, String token) {
        return new YCToken().convertFromString(appKey, appSecret, token);
    }

}