package com.yy.cloud.token;

import com.yy.cloud.token.endecrypt.HmacSHA1Util;
import com.yy.cloud.token.utils.SafeUrlBase64Util;
import com.yy.cloud.token.utils.Bytes;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class YcloudToken {

    private static Logger logger = LoggerFactory.getLogger(YcloudToken.class);

    final private int tokenVersion = -10001001;
    private int tokenLen;
    private int appkey;
    private String uid;
    private Map<String, String> parameterMap;
    private Map<String, Long> privilegesMap;
    private long buildTimestampMills;
    private int validTime;


    public YcloudToken buildToken(int appKey, String vuid) {

        if (StringUtils.isBlank(vuid)) {
            throw new TokenException("ycloudToken vuid can't be blank.");
        }

        this.setAppkey(appKey);
        this.setUid(vuid);
        this.setBuildTimestampMills(System.currentTimeMillis());
        this.setValidTime(30 * 24 * 60 * 60);
        return this;
    }


    public YcloudToken buildToken(int appKey, String vuid, int validTime) {

        if (StringUtils.isBlank(vuid)) {
            throw new TokenException("ycloudToken vuid can't be blank.");
        }

        setAppkey(appKey);
        setUid(vuid);
        setBuildTimestampMills(System.currentTimeMillis());
        setValidTime(validTime);

        return this;
    }

    public YcloudToken buildToken(int appKey, String vuid, int validTime, Map<String, String> parameterMap, Map<String, Long> privilegesMap) {

        if (StringUtils.isBlank(vuid)) {
            throw new TokenException("ycloudToken vuid can't be blank.");
        }

        setAppkey(appKey);
        setUid(vuid);
        setParameterMap(parameterMap);
        setPrivilegesMap(privilegesMap);
        setBuildTimestampMills(System.currentTimeMillis());
        setValidTime(validTime);

        return this;
    }

    public YcloudToken convertFromString(int appKey, String appSecret, String token)
            throws TokenException {
        byte[] tokenByte = null;
        try {
            tokenByte = SafeUrlBase64Util.safeUrlBase64Decode(token);
        } catch (Exception e) {
            throw new TokenException("ycloudToken invalid, saveUrlBase64Decode failed", e);
        }

        //校验token是否合法
        try {
            String tokenStr = tokenBytesBase2Str(tokenByte, appSecret);
            if (!tokenStr.equals(token)) {
                throw new TokenException("ycloudToken undecoded, maybe token invalid or appkey/appSecret invalid.");
            }
        } catch (Exception e) {
            throw new TokenException(e.getMessage(), e);
        }

        try {
            int curr = 0;
            //跳过tokenVersion
            curr += Integer.BYTES;

            //反序列化token长度
            byte[] tokenLenByte = new byte[Integer.BYTES];
            System.arraycopy(tokenByte, curr, tokenLenByte, 0, Integer.BYTES);
            curr += Integer.BYTES;
            this.tokenLen = Bytes.bytes2int(tokenLenByte);

            //反序列化appkey
            byte[] appkeyByte = new byte[Integer.BYTES];
            System.arraycopy(tokenByte, curr, appkeyByte, 0, Integer.BYTES);
            curr += Integer.BYTES;
            this.appkey = Bytes.bytes2int(appkeyByte);
            if (this.appkey != appKey) {
                throw new TokenException(String.format("ycloudToken convertFromString error,appkey unequal[input:%s,intoken:%s]", appKey, String.valueOf(this.appkey)));
            }

            //反序列化uid长度
            byte[] uidLenByte = new byte[Short.BYTES];
            System.arraycopy(tokenByte, curr, uidLenByte, 0, Short.BYTES);
            curr += Short.BYTES;
            short uidLen = Bytes.bytes2short(uidLenByte);

            //反序列化uid
            byte[] uidByte = new byte[uidLen];
            System.arraycopy(tokenByte, curr, uidByte, 0, uidLen);
            this.uid = new String(uidByte, "UTF-8");
            curr += uidLen;

            //反序列化parameter长度
            byte[] parameterLenByte = new byte[Short.BYTES];
            System.arraycopy(tokenByte, curr, parameterLenByte, 0, Short.BYTES);
            short parameterLen = Bytes.bytes2short(parameterLenByte);
            curr += Short.BYTES;

            //反序列化parameterMap
            parameterMap = new HashMap<String, String>();
            for (short i = 0; i < parameterLen; i++) {
                //反序列化mapKey长度
                byte[] keyLenByte = new byte[Short.BYTES];
                System.arraycopy(tokenByte, curr, keyLenByte, 0, Short.BYTES);
                short keyLen = Bytes.bytes2short(keyLenByte);
                curr += Short.BYTES;

                //反序列化mapkey
                byte[] keyByte = new byte[keyLen];
                System.arraycopy(tokenByte, curr, keyByte, 0, keyLen);
                String key = new String(keyByte, "UTF-8");
                curr += keyLen;

                //反序列化mapvalue长度
                byte[] valueLenByte = new byte[Short.BYTES];
                System.arraycopy(tokenByte, curr, valueLenByte, 0, Short.BYTES);
                short valueLen = Bytes.bytes2short(valueLenByte);
                curr += Short.BYTES;

                //反序列化mapvalue
                byte[] valueByte = new byte[valueLen];
                System.arraycopy(tokenByte, curr, valueByte, 0, valueLen);
                String value = new String(valueByte, "UTF-8");
                curr += valueLen;

                parameterMap.put(key, value);
            }

            //反序列化privilgesMap长度
            byte[] privilgesLenByte = new byte[Short.BYTES];
            System.arraycopy(tokenByte, curr, privilgesLenByte, 0, Short.BYTES);
            short privilegesLen = Bytes.bytes2short(privilgesLenByte);
            curr += Short.BYTES;

            //反序列化privilgesMap
            privilegesMap = new HashMap<String, Long>();
            for (short i = 0; i < privilegesLen; i++) {
                //反序列化mapKey长度
                byte[] keyLenByte = new byte[Short.BYTES];
                System.arraycopy(tokenByte, curr, keyLenByte, 0, Short.BYTES);
                short keyLen = Bytes.bytes2short(keyLenByte);
                curr += Short.BYTES;

                //反序列化mapkey
                byte[] keyByte = new byte[keyLen];
                System.arraycopy(tokenByte, curr, keyByte, 0, keyLen);
                String key = new String(keyByte, "UTF-8");
                curr += keyLen;

                //反序列化mapvalue
                byte[] valueByte = new byte[Long.BYTES];
                System.arraycopy(tokenByte, curr, valueByte, 0, Long.BYTES);
                long value = Bytes.bytes2long(valueByte);
                curr += Long.BYTES;

                privilegesMap.put(key, value);
            }

            //反序列化buildTimestampMills
            byte[] buildTimestampMillsByte = new byte[Long.BYTES];
            System.arraycopy(tokenByte, curr, buildTimestampMillsByte, 0, Long.BYTES);
            this.buildTimestampMills = Bytes.bytes2long(buildTimestampMillsByte);
            curr += Long.BYTES;

            //反序列化validTime
            byte[] validTimeByte = new byte[Integer.BYTES];
            System.arraycopy(tokenByte, curr, validTimeByte, 0, Integer.BYTES);
            this.validTime = Bytes.bytes2int(validTimeByte);

            logger.info("ycloudToken[tokenVersion:" + tokenVersion + ",appkey:" + appKey + ",token:" + token + ",appSecret length:" + appSecret.length()
                    + ",vuid:" + uid + ",buildTimestampMills:" + buildTimestampMills + ",validTime:" + validTime + "]");

            return this;
        } catch (Exception e) {
            throw new TokenException("ycloudToken convertFromString error", e);
        }
    }

    public String convertToString(String appSecret) throws TokenException {

        try {
            //序列化tokenVersion
            byte[] tokenVersionByte = Bytes.int2bytes(tokenVersion);
            //序列化appkey
            byte[] appKeyByte = Bytes.int2bytes(appkey);
            //序列化uid
            byte[] uidByte = uid.getBytes("UTF-8");
            if (uid.length() > Short.MAX_VALUE) {
                throw new TokenException();
            }
            //序列化uid长度
            byte[] uidLenByte = Bytes.short2bytes((short) uid.length());

            //序列化parameterMap长度
            byte[] parameterMapLenByte;
            if (parameterMap == null) {
                parameterMapLenByte = Bytes.short2bytes((short) 0);
            } else {
                parameterMapLenByte = Bytes.short2bytes((short) parameterMap.size());
            }
            //序列化parameterMap
            byte[] parameterMapByte = parameterMapToByteArr(parameterMap);

            //序列化privilegesMap长度
            byte[] privilegesMapLenByte;
            if (privilegesMap == null) {
                privilegesMapLenByte = Bytes.short2bytes((short) 0);
            } else {
                privilegesMapLenByte = Bytes.short2bytes((short) privilegesMap.size());
            }
            //序列化privilegesMap
            byte[] privilegesMapByte = privilegesMapToByteArr(privilegesMap);

            //序列化buildTimestampMills
            byte[] buildTimestampMillsByte = Bytes.long2bytes(buildTimestampMills);
            //序列化validTime
            byte[] validTimeByte = Bytes.int2bytes(validTime);

            //计算整个token的长度
            this.tokenLen = tokenVersionByte.length + appKeyByte.length + uidByte.length + uidLenByte.length + parameterMapByte.length + privilegesMapByte.length
                    + parameterMapLenByte.length + privilegesMapLenByte.length + buildTimestampMillsByte.length + validTimeByte.length
                    + 4 + 20;
            //序列化token长度
            byte[] tokenLenByte = Bytes.int2bytes(tokenLen);

            //把以上各项数据（没有数字签名）序列化的结果按照协议规定的字段顺序拷贝到tokenByte；
            byte[] tokenByte = new byte[tokenLen];
            int curr = 0;
            System.arraycopy(tokenVersionByte, 0, tokenByte, 0, tokenVersionByte.length);
            curr += tokenVersionByte.length;
            System.arraycopy(tokenLenByte, 0, tokenByte, curr, tokenLenByte.length);
            curr += tokenLenByte.length;
            System.arraycopy(appKeyByte, 0, tokenByte, curr, appKeyByte.length);
            curr += appKeyByte.length;
            System.arraycopy(uidLenByte, 0, tokenByte, curr, uidLenByte.length);
            curr += uidLenByte.length;
            System.arraycopy(uidByte, 0, tokenByte, curr, uidByte.length);
            curr += uidByte.length;
            System.arraycopy(parameterMapLenByte, 0, tokenByte, curr, parameterMapLenByte.length);
            curr += parameterMapLenByte.length;
            System.arraycopy(parameterMapByte, 0, tokenByte, curr, parameterMapByte.length);
            curr += parameterMapByte.length;
            System.arraycopy(privilegesMapLenByte, 0, tokenByte, curr, privilegesMapLenByte.length);
            curr += privilegesMapLenByte.length;
            System.arraycopy(privilegesMapByte, 0, tokenByte, curr, privilegesMapByte.length);
            curr += privilegesMapByte.length;
            System.arraycopy(buildTimestampMillsByte, 0, tokenByte, curr, buildTimestampMillsByte.length);
            curr += buildTimestampMillsByte.length;
            System.arraycopy(validTimeByte, 0, tokenByte, curr, validTimeByte.length);

            //计算签名并存放在tokenByte的后20字节，再对整个tokenByte进行url安全的base64
            return tokenBytesBase2Str(tokenByte, appSecret);

        } catch (Exception e) {
            throw new TokenException("product ycloudToken string failed", e);
        }

    }

    private byte[] parameterMapToByteArr(Map<String, String> srcMap) throws Exception {

        if (srcMap == null || srcMap.isEmpty()) {
            return new byte[0];
        } else {
            List<Byte> parameterMapByte = new ArrayList<Byte>();
            for (String key : srcMap.keySet()) {
                byte[] keyByte = key.getBytes("UTF-8");
                if (keyByte.length > Short.MAX_VALUE) {
                    throw new TokenException("parameterMapkey:" + key + " is too long");
                }

                short keyByteLen = (short) keyByte.length;
                for (byte b : Bytes.short2bytes(keyByteLen)) {
                    parameterMapByte.add(b);
                }

                for (byte b : keyByte) {
                    parameterMapByte.add(b);
                }

                String value = srcMap.get(key);
                byte[] valueByte = value.getBytes("UTF-8");
                if (valueByte.length > Short.MAX_VALUE) {
                    throw new TokenException("parameterMapvalue:" + value + " is too long");
                }

                short valueByteLen = (short) valueByte.length;
                for (byte b : Bytes.short2bytes(valueByteLen)) {
                    parameterMapByte.add(b);
                }

                for (byte b : valueByte) {
                    parameterMapByte.add(b);
                }
            }

            byte[] resultByteArry = new byte[parameterMapByte.size()];
            for (int i = 0; i < parameterMapByte.size(); i++) {
                resultByteArry[i] = parameterMapByte.get(i);
            }

            return resultByteArry;
        }
    }

    private byte[] privilegesMapToByteArr(Map<String, Long> srcMap) throws Exception {
        if (srcMap == null || srcMap.isEmpty()) {
            return new byte[0];
        } else {
            List<Byte> privilegesMapByte = new ArrayList<Byte>();
            for (String key : srcMap.keySet()) {
                byte[] keyByte = key.getBytes("UTF-8");
                if (keyByte.length > Short.MAX_VALUE) {
                    throw new TokenException("parameterMapkey:" + key + " is too long");
                }

                short keyByteLen = (short) keyByte.length;
                for (byte b : Bytes.short2bytes(keyByteLen)) {
                    privilegesMapByte.add(b);
                }


                for (byte b : keyByte) {
                    privilegesMapByte.add(b);
                }

                byte[] valueByte = Bytes.long2bytes(srcMap.get(key));
                for (byte b : valueByte) {
                    privilegesMapByte.add(b);
                }
            }
            byte[] resultByteArry = new byte[privilegesMapByte.size()];
            for (int i = 0; i < privilegesMapByte.size(); i++) {
                resultByteArry[i] = privilegesMapByte.get(i);
            }

            return resultByteArry;
        }
    }

    private String tokenBytesBase2Str(byte[] tokenByte, String appSecret) throws Exception {
        byte[] rawHmac = HmacSHA1Util.hmac(Arrays.copyOfRange(tokenByte, 0, tokenByte.length - 20), appSecret);
        System.arraycopy(rawHmac, 0, tokenByte, tokenByte.length - 20, 20);
        return SafeUrlBase64Util.safeUrlBase64Encode(tokenByte);
    }

    public boolean validToken(int appKey, String vuid) throws TokenException {
        return this.validToken(appKey, vuid, -1);
    }

    public boolean validToken(int appKey, String vuid, long forceExpiredTimestampMills) throws TokenException {
        if (this.appkey != appKey) {
            throw new TokenException("The ycloudToken appKey is invalid.");
        }

        if (!this.uid.equals(vuid)) {
            throw new TokenException("The ycloudToken vuid is invalid.");
        }

        if (System.currentTimeMillis() > buildTimestampMills + (long) validTime * 1000) {
            throw new TokenException("The ycloudToken is expire because currentTime is greater than expireTime.");
        }

        if (buildTimestampMills <= forceExpiredTimestampMills) {
            throw new TokenException(String.format("The ycloudToken is expire because buildTime is less than forced expired Time-%s.", forceExpiredTimestampMills));
        }

        return true;
    }

    public boolean isValidToken(int appkey, String vuid) {
        if (this.appkey != appkey || !this.uid.equals(vuid)) {
            return false;
        }

        return System.currentTimeMillis() <= buildTimestampMills + (long) validTime * 1000;
    }

    public boolean isValidToken(int appkey, String vuid, long forceExpiredTimestampMills) {
        if (this.appkey != appkey || !this.uid.equals(vuid)) {
            return false;
        }

        return System.currentTimeMillis() <= buildTimestampMills + (long) validTime * 1000 && buildTimestampMills > forceExpiredTimestampMills;
    }

    public int getTokenLen() {
        return tokenLen;
    }

    public void setTokenLen(int tokenLen) {
        this.tokenLen = tokenLen;
    }

    public int getAppkey() {
        return appkey;
    }

    public void setAppkey(int appkey) {
        this.appkey = appkey;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public Map<String, String> getParameterMap() {
        return parameterMap;
    }

    public void setParameterMap(Map<String, String> parameterMap) {
        this.parameterMap = parameterMap;
    }

    public Map<String, Long> getPrivilegesMap() {
        return privilegesMap;
    }

    public void setPrivilegesMap(Map<String, Long> privilegesMap) {
        this.privilegesMap = privilegesMap;
    }

    public long getBuildTimestampMills() {
        return buildTimestampMills;
    }

    public void setBuildTimestampMills(long buildTimestampMills) {
        this.buildTimestampMills = buildTimestampMills;
    }

    public int getValidTime() {
        return validTime;
    }

    public void setValidTime(int validTime) {
        this.validTime = validTime;
    }
}
