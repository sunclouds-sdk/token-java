package com.yy.cloud.token.test;

import com.yy.cloud.token.YcloudToken;
import com.yy.cloud.token.factory.YcloudTokenFactory;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class YcloudTokenTest {

    private YcloudTokenFactory factory = YcloudTokenFactory.getInstance();
    private static Logger logger = LoggerFactory.getLogger(YcloudToken.class);

    @Test
    public void testCreateToken() {
        Map<String, String> parameterMap = new HashMap<String, String>();
        parameterMap.put("fdy", "soie4");
        parameterMap.put("442cd", "fdsaf545");
        parameterMap.put("你", "好");

        Map<String, Long> privilegeMap = new HashMap<String, Long>();
        privilegeMap.put("fdy", 1234503540L);
        privilegeMap.put("442cd", 12345453540L);
        privilegeMap.put("你", 123412133540L);

        String ycloudTokenStr = factory.createToken(132154, "5461235ss", 132123, parameterMap, privilegeMap, "2aeeb8de_3");
        logger.info("token:" + ycloudTokenStr);

    }

    @Test
    public void validToken() {
        YcloudToken ycloudToken = factory.convertFromString(132154, "2aeeb8de_3", "_2dllwAAAIsAAgQ6AAk1NDYxMjM1c3MAAwAD5L2gAAPlpb0ABTQ0MmNkAAhmZHNhZjU0NQADZmR5AAVzb2llNAADAAPkvaAAAAAcu--2pAAFNDQyY2QAAAAC39ir5AADZmR5AAAAAEmVB3QAAAFsg_xX_QACBBsDsrYj2KqDrwNWInmBF2AHZEK0aA");
        logger.info("token appkey:" + String.valueOf(ycloudToken.getAppkey()));
        logger.info("token buildTimestamp:" + String.valueOf(ycloudToken.getBuildTimestampMills()));
        logger.info("token parameterMap:" + String.valueOf(ycloudToken.getParameterMap()));
        logger.info("token privilegesMap:" + String.valueOf(ycloudToken.getPrivilegesMap()));
        logger.info("token len:" + String.valueOf(ycloudToken.getTokenLen()));
        logger.info("token userId:" + String.valueOf(ycloudToken.getUid()));
        logger.info("token validTime:" + String.valueOf(ycloudToken.getValidTime()) + "秒");
        logger.info("token valid:" + String.valueOf(ycloudToken.isValidToken(132154, "5461235ss")));
    }
}
