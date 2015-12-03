package org.g4.certificate.utilities;

import org.g4.certificate.exception.CGVRuntimeException;
import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Unit test for CertUtil
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertUtilTest {
    @Test
    public void isNull() {
        assertTrue(CertUtil.isNull(""));
        assertTrue(CertUtil.isNull("    "));
        assertTrue(CertUtil.isNull(null));
    }

    @Test
    public void isNum(){
        assertTrue(CertUtil.isNum("9"));
        assertTrue(CertUtil.isNum("99"));
        assertFalse(CertUtil.isNum("9.2"));
        assertFalse(CertUtil.isNum("-12"));
        assertFalse(CertUtil.isNum("abc"));
    }

    @Test
    public void convertMapToDName() {
        Map<String, String> dnMap = new HashMap<String, String>();
        dnMap.put("CN", "idmvm15");
        dnMap.put("OU", "HPSW");
        dnMap.put("O", "HP");
        dnMap.put("L", "SH");
        dnMap.put("ST", "SH");
        dnMap.put("C", "CN");

        assertEquals("\"CN=idmvm15,OU=HPSW,O=HP,L=SH,ST=SH,C=CN\"", CertUtil.convertMapToDName(dnMap, 0));
        assertEquals("\"/C=CN/ST=SH/L=SH/O=HP/OU=HPSW/CN=idmvm15\"", CertUtil.convertMapToDName(dnMap, 1));

        dnMap.put("emailAddress", "admin@admin.com");
        assertEquals("\"/C=CN/ST=SH/L=SH/O=HP/OU=HPSW/CN=idmvm15/emailAddress=admin@admin.com\"", CertUtil.convertMapToDName(dnMap, 1));

        assertNull(CertUtil.convertMapToDName(dnMap, 3));

    }

    @Test
    public void getDefaultDName() {
        assertEquals("\"CN=idmvm15,OU=HPSW,O=HP,L=Shanghai,ST=Shanghai,C=CN\"", CertUtil.getDefaultDName(0, "idmvm15"));
        assertEquals("\"/CN=idmvm15/OU=HPSW/O=HP/L=Shanghai/ST=Shanghai/C=CN/emailAddress=admin@hp.com\"", CertUtil.getDefaultDName(1, "idmvm15"));
        try {
            CertUtil.getDefaultDName(3, "");
            fail("the type value should only be 0 or 1");
        } catch (CGVRuntimeException e) {
            assertEquals("invalid type of default dname", e.getMessage());
        }
    }

    @Test
    public void isInScope() {
        String[] valueArray = null;
        assertFalse(CertUtil.isInScope("", valueArray));

        valueArray = new String[]{"Johnson", "Peter", "Gary"};
        assertTrue(CertUtil.isInScope("Johnson", valueArray));
        assertFalse(CertUtil.isInScope("Perry", valueArray));
    }


    @Test
    public void getCommandStr() {
        List<String> commandList = new ArrayList<String>();
        assertEquals("", CertUtil.getCommandStr(commandList));

        commandList.add("Hello");
        commandList.add("World");
        assertEquals("Hello World ", CertUtil.getCommandStr(commandList));

    }

    @Test
    public void getSpace() {
        assertEquals("   ", CertUtil.getSpace(3));
        assertEquals("", CertUtil.getSpace(4, ""));
        assertEquals("   ", CertUtil.getSpace(5, "ab"));
    }

}
