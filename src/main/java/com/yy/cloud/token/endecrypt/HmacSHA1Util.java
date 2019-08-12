package com.yy.cloud.token.endecrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HmacSHA1Util {

    public static byte[] hmac(byte[] data, String secret) throws Exception {

        SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA1");
        Mac mac = Mac.getInstance(signingKey.getAlgorithm());
        mac.init(signingKey);
        return mac.doFinal(data);

    }
}
