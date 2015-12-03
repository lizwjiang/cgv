package org.g4.certificate;

import org.g4.certificate.facade.CertLogger;

import java.io.UnsupportedEncodingException;

/**
 * Created with IntelliJ IDEA.
 * User: Johnson Jiang
 * Date: 11/6/13
 * Time: 5:08 PM
 */
public class Test {
    public static void main(String[] args) throws UnsupportedEncodingException {
       /* Map m = System.getenv();

        for (Iterator it = m.keySet().iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            String value = (String) m.get(key);
            System.out.println(key + " : " + value);

        }*/

      /* Properties p = System.getProperties();
        p.setProperty("file.separator","/");
        for ( Iterator it = p.keySet().iterator(); it.hasNext(); ){
            String key = (String ) it.next();
            String value = (String )  p.get(key);
            System.out.println(key +" = " +value);
        }*/
      /*  System.out.println(Test.class.getResource("/").getPath().toString());

        String s = "c:\\abc\\123.keystore";

        System.out.println(System.getProperty("jre.home"));

        String url = Test.class.getProtectionDomain().getCodeSource().getLocation().getFile();
        String l = URLDecoder.decode(Test.class.getProtectionDomain().getCodeSource().getLocation().getFile(), "UTF-8");

        System.out.println(l);

        Reader reader  =new InputStreamReader(Test.class.getClassLoader().getResourceAsStream("/a.txt"));*/

        /*String currentPath = Test.class.getResource("/").getPath().toString();
        System.out.println(currentPath);

        FileUtil.createFile(currentPath + "Johnson_test.txt");

        try {
            //1. Class.getResourceAsStream(String path), if the path doesn't start with /, the path will be started from the package the current class belongs to,
            //if starting with /, that means the path will be started from the root of classpath.
            //2. Class.getClassLoader.getResourceAsStream(String path), by default, the path is started from the root of classpath, so the path should not start with /
            InputStream is = Test.class.getResourceAsStream("/com/hp/servicemanager/certificate/resources/openssl.exe");
            if(is == null) System.out.println(" is is null");
            FileUtil.createFile(is, "c:/openssl.exe");
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }*/
        //System.out.println(FileUtil.getJarCurrentPath());
        //CertGen.generateAllCertificates4SMTSO();
       /* File f = new File("C:/Program Files (x86)/Java/jre7/lib/security/cacerts");
        if(f.exists()) System.out.println("file exists");*/

        /*String path = "abcde123/";
        path = path.substring(0, path.lastIndexOf("/"));
        System.out.println(path);*/
/*
        String cmd="D:/Program Files (x86)";
        System.out.println(CertUtil.analyzeSpace(cmd));*/

        /*String cmd[] = new String[]{
                "cmd ", "/c",
                "start",
                "keytool",
                "-genkey"};


        CertificateExecutor.execCommand(cmd, new File("C:/Program Files (x86)/Java/jre7/bin"));*/
      /*  Runtime runtime = Runtime.getRuntime();
        NumberFormat format = NumberFormat.getInstance();

        StringBuilder sb = new StringBuilder();
        long maxMemory = runtime.maxMemory();
        long allocatedMemory = runtime.totalMemory();
        long freeMemory = runtime.freeMemory();

        sb.append("free memory: " + format.format(freeMemory / (1024 * 1024)) + " MB\n");
        sb.append("allocated memory: " + format.format(allocatedMemory / (1024 * 1024)) + " MB\n");
        sb.append("max memory: " + format.format(maxMemory / (1024 * 1024)) + "MB\n");
        sb.append("total free memory: " + format.format((freeMemory + (maxMemory - allocatedMemory)) / (1024 * 1024)) + "MB\n");


        System.out.println(sb.toString());*/

       /* String path = "E:\\TSO_test\\TSO";

        FileUtil.getFileList(path);

        Map<String, String> testMap = new HashMap<String, String>();

        testMap.put("test1","test1");

        testMap.put("test","");

        String abc = testMap.get("test");
        System.out.println(abc);*/
        //KeyToolFacade.getEnvJREPath();
/*
        CertLogger logger = CertLogger.getLogger("test");
        logger.info("Test");*/

        CertLogger logger = CertLogger.getLogger(Test.class.getName());
        logger.debug("Johnson testing.........................................................");
    }
}
