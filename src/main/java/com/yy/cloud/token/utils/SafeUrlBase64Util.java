package com.yy.cloud.token.utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

public class SafeUrlBase64Util {
    public static String safeUrlBase64Encode(byte[] data) {

        String encodeBase64 = new BASE64Encoder().encode(data);

        String safeBase64Str = encodeBase64.replace('+', '-');

        safeBase64Str = safeBase64Str.replace('/', '_');

        safeBase64Str = safeBase64Str.replaceAll("=", "");

        safeBase64Str = safeBase64Str.replaceAll("[\\s*\t\n\r]", "");

        return safeBase64Str;

    }

    public static byte[] safeUrlBase64Decode(final String safeBase64Str) throws Exception {

        String base64Str = safeBase64Str.replace('-', '+');

        base64Str = base64Str.replace('_', '/');

        int mod4 = base64Str.length() % 4;

        if (mod4 > 0) {

            base64Str = base64Str + "====".substring(mod4);

        }

        return new BASE64Decoder().decodeBuffer(base64Str);

    }
}
