package org.g4.certificate.utilities;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

import java.io.*;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Unit test for FileUtil
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class FileUtilTest {
    String rootFolder;
    String helloWorldFile = "helloworld.txt";

    @Before
    public void setUp() {
        rootFolder = FileUtil.getJarCurrentPath() + "CGA_TEST\\";
        String helloWorld = "Hello World";
        try {
            File dir = new File(rootFolder);
            if (!dir.exists()) {
                dir.mkdir();
            }
            File f = new File(rootFolder + helloWorldFile);
            if (!f.exists())
                f.createNewFile();
            FileWriter fw = new FileWriter(f);
            PrintWriter pw = new PrintWriter(fw);
            pw.append(helloWorld);
            pw.flush();
            pw.close();
        } catch (Exception e) {
            fail("Errors happen when trying to create folders and files");
        }


    }

    @Test
    public void createFile() {
        String tempStr = "test create file";
        FileUtil.createFile(new ByteArrayInputStream(tempStr.getBytes()), rootFolder + "myTemp.txt");
        File f = new File(rootFolder + "myTemp.txt");
        assertTrue(f.exists() && f.isFile());
        assertEquals("test create file", readFile(rootFolder + "myTemp.txt"));

        String myFile1 = rootFolder + "myFile1.txt";
        boolean rtn = FileUtil.createFile(rootFolder + helloWorldFile, myFile1);
        assertTrue(rtn);
        File ff = new File(myFile1);
        assertTrue(ff.exists() && ff.isFile());
        assertEquals("Hello World", readFile(myFile1));

    }

    @Test
    public void createDir() {
        String dir = rootFolder + "testFolder1";
        boolean rtn = FileUtil.createDir(dir);
        assertTrue(rtn);

        File f = new File(dir);
        assertTrue(f.exists() && f.isDirectory());

        rtn = FileUtil.createDir(rootFolder + File.separator + "aaa" + File.separator + "bbb");
        assertFalse(rtn);
    }

    @Test
    public void deleteDir() {
        String folder2 = rootFolder + "testFolder2";
        String folder3 = rootFolder + "testFolder2" + File.separator + "testFolder3";
        String folder4 = rootFolder + "testFolder2" + File.separator + "testFolder4";
        FileUtil.createDir(folder2);
        FileUtil.createDir(folder3);
        FileUtil.createDir(folder4);

        boolean rtn = FileUtil.deleteDir(folder2);
        assertTrue(rtn);
        File f = new File(folder2);
        assertFalse(f.exists());
    }

    @Test
    public void deleteFile() {
        String tempStr = "test create file";
        String myDelFile = rootFolder + "myDelFile.txt";
        FileUtil.createFile(new ByteArrayInputStream(tempStr.getBytes()), myDelFile);
        File f = new File(myDelFile);
        assertTrue(f.exists());

        boolean rtn = FileUtil.deleteFile(myDelFile);
        assertTrue(rtn);
        File delFile = new File(myDelFile);
        assertFalse(delFile.exists());
    }

    @Test
    public void getFileNameList() {
        String testFolder = rootFolder + "fileNameList";
        FileUtil.createDir(testFolder);
        FileUtil.createFile(rootFolder + helloWorldFile, testFolder + File.separator + "a.txt");
        FileUtil.createFile(rootFolder + helloWorldFile, testFolder + File.separator + "b.txt");

        List<String> fileNameList = FileUtil.getFileNameList(testFolder);
        int count = 0;
        for (String fileName : fileNameList) {
            if (fileName.equals("a.txt")) {
                count++;
            } else if (fileName.equals("b.txt")) {
                count++;
            }
        }
        if (count != 2) {
            fail("No get the correct file name list");
        }
    }

    @Test
    public void getDirNameList() {
        String testFolder = rootFolder + "dirNameList";
        FileUtil.createDir(testFolder);
        FileUtil.createDir(testFolder + File.separator + "dirNameFolder1");
        FileUtil.createDir(testFolder + File.separator + "dirNameFolder2");

        List<String> dirNameList = FileUtil.getDirNameList(testFolder);
        int count = 0;
        for (String dirName : dirNameList) {
            if (dirName.equals("dirNameFolder1")) {
                count++;
            } else if (dirName.equals("dirNameFolder2")) {
                count++;
            }
        }
        if (count != 2) {
            fail("No get the correct folder name list");
        }
    }

    @Test
    public void isFile() {
        assertTrue(FileUtil.isFile(rootFolder + helloWorldFile));
        assertFalse(FileUtil.isFile(rootFolder + "aaabbbcccddd.txt"));
    }


    @Test
    public void isDir() {
        assertTrue(FileUtil.isDir(rootFolder));
        assertFalse(FileUtil.isDir(rootFolder + "aaabbbccccddd"));
    }

    @Test
    public void getFileName() {
        assertEquals(helloWorldFile, FileUtil.getFileName(rootFolder + helloWorldFile));
    }

    @After
    public void tearDown() {
        FileUtil.deleteDir(rootFolder);
    }

    private String readFile(String file) {
        FileReader fr = null;
        BufferedReader br = null;

        StringBuffer sb = new StringBuffer();
        try {
            fr = new FileReader(file);
            br = new BufferedReader(fr);
            String s = null;
            while ((s = br.readLine()) != null) {
                sb.append(s);
            }
        } catch (Exception e) {
            fail("Error happens when reading file");
        } finally {

            try {
                if (br != null) {
                    br.close();
                }
                if (fr != null) {
                    fr.close();
                }
            } catch (Exception e) {
                fail("Error happens when closing bufferedReader and FileReader");
            }
        }
        return sb.toString();
    }
}
