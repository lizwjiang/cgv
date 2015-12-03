package org.g4.certificate.utilities;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit test for PropertiesAnalyzerTest
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class PropertiesAnalyzerTest {
    String rootFolder;
    String testFile = "test.conf";

    @Before
    public void setUp() {
        rootFolder = FileUtil.getJarCurrentPath() + "CGA_PROPS_TEST\\";

        String str1 = "server.list=server1,server2";
        String str2 = "client.list=client1,client2";
        try {
            File dir = new File(rootFolder);
            if (!dir.exists()) {
                dir.mkdir();
            }
            File f = new File(rootFolder + testFile);
            if (!f.exists())
                f.createNewFile();
            FileWriter fw = new FileWriter(f);
            PrintWriter pw = new PrintWriter(fw);
            pw.append(str1).append("\r\n").append(str2);
            pw.flush();
            pw.close();
            fw.close();
        } catch (Exception e) {
            fail("Errors happen when trying to create folders and files");
        }

    }

    @Test
    public void convertProperties2Map(){
        Map<String, String> paramMap = PropertiesAnalyzer.convertProperties2Map(rootFolder + testFile);
        assertEquals("server1,server2", paramMap.get("server.list"));
        assertEquals("client1,client2", paramMap.get("client.list"));
    }

    @After
    public void tearDown() {
        boolean flag = FileUtil.deleteDir(rootFolder);
        assertTrue(flag);
    }
}
