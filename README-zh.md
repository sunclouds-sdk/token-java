# YCToken
本文介绍了java版YCToken SDK的使用方法，并提供了产YCToken和验YCToken的代码示例。

## 描述
YCToken能够支持身份验证和过期时间验证，并支持业务参数的透传（不对业务参数进行校验）。

## 示例代码
#### 产YCToken
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

#### 验YCToken
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
 
## 其他语言的YCToken SDK
其他语言的YCToken SDK及它们的介绍、相关示例代码地址如下：
 
### golang

+ https://github.com/sunclouds-sdk/token-golang

### python

+ https://github.com/sunclouds-sdk/token-python

> 你可以使用YCToke实例代码完成产TCToken和验TCToken。
