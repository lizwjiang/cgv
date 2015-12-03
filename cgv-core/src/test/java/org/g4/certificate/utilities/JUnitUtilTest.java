package org.g4.certificate.utilities;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Unit test for JUnitUtil
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class JUnitUtilTest {

    private String getName(String key, Map<String, String> map){
        return map.get(key);
    }

    @Test
    public void getTestResult(){
        JUnitUtilTest t = new JUnitUtilTest();
        Map<String,String> map = new HashMap<String, String>();
        map.put("key1", "value1");
        map.put("key2", "value2");

        String value = (String)JUnitUtil.getTestResult(t, "getName",new Class[]{String.class, Map.class}, new Object[]{"key1", map});

        assertEquals("value1", value);
    }
}
