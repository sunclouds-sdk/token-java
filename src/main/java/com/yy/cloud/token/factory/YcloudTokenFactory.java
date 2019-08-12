package com.yy.cloud.token.factory;

import com.yy.cloud.token.YcloudToken;

import java.util.Map;

public class YcloudTokenFactory {

    private static YcloudTokenFactory ycloudTokenFactory = new YcloudTokenFactory();

    public static YcloudTokenFactory getInstance() {

        if (ycloudTokenFactory == null) {
            synchronized (YcloudTokenFactory.class) {
                if (ycloudTokenFactory == null) {
                    ycloudTokenFactory = new YcloudTokenFactory();
                }
            }
        }
        return ycloudTokenFactory;
    }

    private YcloudTokenFactory() {

    }

    public String createToken(int appKey, String vuid, String appSecret) {
        return new YcloudToken().buildToken(appKey, vuid).convertToString(appSecret);
    }

    public String createToken(int appKey, String vuid, int validTime, String appkey) {
        return new YcloudToken().buildToken(appKey, vuid, validTime).convertToString(appkey);
    }

    public String createToken(int appKey, String vuid, int validTime, Map<String, String> parameterMap, Map<String, Long> privilegesMap, String appSecret) {
        return new YcloudToken().buildToken(appKey, vuid, validTime, parameterMap, privilegesMap).convertToString(appSecret);
    }

    public YcloudToken convertFromString(int appKey, String appSecret, String token) {
        return new YcloudToken().convertFromString(appKey, appSecret, token);
    }

}