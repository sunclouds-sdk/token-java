# YCToken
This page describes the authentication mechanism used by the YCToken SDK of java version, as well as providing the related code for generating and verifying YCToken(v1.0.0).

## Description
YCToken is able to support verification of identity and verification of expiry time. it support the transfer of business parameters, but it doesn't check the business parameters.

## Java Sample Code
#### Generate YCToken
```
import com.yy.cloud.token.factory.YCTokenFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class YCTokenTest {

    private static YCTokenFactory factory = YCTokenFactory.getInstance();
    private static Logger logger = LoggerFactory.getLogger(YCTokenTest.class);

    public static void main(String[] args) {
        final int appkey = 132154;
        final String uid = "5461235ss";
        final int validTime = 1576800000;   //秒数
        final String appSecret = "2aeeb8de_3";

        //参数map
        Map<String, String> parameterMap = new HashMap<String, String>();
        parameterMap.put("pTest1Key", "pTest1Val");
        parameterMap.put("pTest2Key", "pTest2Val");
        parameterMap.put("测试key1", "测试值1");

        //鉴权map
        Map<String, Long> privilegeMap = new HashMap<String, Long>();
        privilegeMap.put("pTest1Key", 1234503540L);
        privilegeMap.put("pTest2Key", 12345453540L);
        privilegeMap.put("测试key1", 123412133540L);

        String YCTokenStr = factory.createToken(appkey, uid, validTime, parameterMap, privilegeMap, appSecret);
        logger.info("token:" + YCTokenStr);
    }
}
```

#### Verify YCToken
```
import com.yy.cloud.token.factory.YCTokenFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class YCTokenTest {

    private static YCTokenFactory factory = YCTokenFactory.getInstance();
    private static Logger logger = LoggerFactory.getLogger(YCTokenTest.class);

    public static void main(String[] args) {
        int appkey = 132154;
        String appSecret = "2aeeb8de_3";
        YCToken YCToken = factory.convertFromString(appkey, appSecret, "_2dllwAAALkAAgQ6AAk1NDYxMjM1c3MAAwAJcFRlc3QxS2V5AAlwVGVzdDFWYWwACua1i-ivlWtleTEACua1i-ivleWAvDEACXBUZXN0MktleQAJcFRlc3QyVmFsAAMACXBUZXN0MUtleQAAAABJlQd0AArmtYvor5VrZXkxAAAAHLvvtqQACXBUZXN0MktleQAAAALf2KvkAAABbJOK1n9d_A8AICKVht3MwiFT6IClKMcSNroRwUw");
        logger.info("token appkey:" + String.valueOf(YCToken.getAppkey()));
        logger.info("token buildTimestamp:" + String.valueOf(YCToken.getBuildTimestampMills()));
        logger.info("token parameterMap:" + String.valueOf(YCToken.getParameterMap()));
        logger.info("token privilegesMap:" + String.valueOf(YCToken.getPrivilegesMap()));
        logger.info("token len:" + String.valueOf(YCToken.getTokenLen()));
        logger.info("token userId:" + String.valueOf(YCToken.getUid()));
        logger.info("token validTime:" + String.valueOf(YCToken.getValidTime()) + "秒");
        logger.info("token valid:" + String.valueOf(YCToken.isValidToken(132154, "5461235ss")));

    }
}
```
 
## Other Language YCToken SDK
Address of other language version YCToken SDKs and the SDKs' description are as follows. Sample code for generating and verifying 
YCToken are also available on this platforms:
 + Golang
 + Python
 
### golang

+ https://github.com/sunclouds-sdk/token-golang

### python

+ https://github.com/sunclouds-sdk/token-python

> You can use YCToken sample code to generate and verify an YCToken.
