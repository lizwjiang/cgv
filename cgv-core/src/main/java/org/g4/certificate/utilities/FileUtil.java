package org.g4.certificate.utilities;

import java.io.*;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;

/**
 * Utilities used to handle anything related to file or directory
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class FileUtil {

    /**
     * Get the current path the current jar file
     *
     * @return
     */
    public static String getJarCurrentPath() {
        String jarURLPath = null;
        try {
            jarURLPath = URLDecoder.decode(FileUtil.class.getProtectionDomain().getCodeSource().getLocation().getFile(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            CertExceptionHandler.handleException(e, "Error happens when getting the current path");
        }
        String jarPath = new File(jarURLPath).getParent();
        return jarPath.endsWith(File.separator) ? jarPath : jarPath + File.separator;
    }

    /**
     * Using the below method to get input stream of the files in Jar
     *
     * @param file The path is based on jar path. for example, if file is /com/hp/aaa.txt in jar, the absolute path
     *             should be {jar path}/com/hp/aaa.txt
     * @return
     */
    public static InputStream getRelativeInputStream(String file) {
        return FileUtil.class.getResourceAsStream(file);
    }

    /**
     * Create a file from the input stream
     * @param is
     * @param outFile
     */
    public static boolean createFile(InputStream is, String outFile) {
        byte[] buffer = new byte[4 * 1024];
        FileOutputStream os = null;

        try {
            os = new FileOutputStream(outFile);
            int read;
            while ((read = is.read(buffer)) > 0) {
                os.write(buffer, 0, read);
            }
        } catch (Exception e) {
            CertExceptionHandler.handleException(e, "Error happens when create the file : " + outFile);
        }finally{
            try{
                os.close();
                is.close();
            }catch(IOException ioe){
                CertExceptionHandler.handleException(ioe, "Error happens on closing the input stream and output steam  during creating file : " + outFile);
            }
        }
        return true;
    }

    /**
     * Copy a file
     *
     * @param file
     * @param outFile
     */
    public static boolean createFile(String file, String outFile) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(new File(file));
        } catch (FileNotFoundException e) {
            CertExceptionHandler.handleException(e, "Error happens when getting the input stream of " + file);
        }
        return createFile(fis, outFile);
    }

    /**
     * Create a new folder
     *
     * @param dir
     */
    public static boolean createDir(String dir) {
        File f = new File(dir);
        return f.mkdir();
    }

    /**
     * delete a folder including all child folders
     *
     * @param dir
     * @return
     */
    public static boolean deleteDir(String dir) {
        return deleteDir(new File(dir));
    }

    public static boolean deleteDir(File dir) {
        if (dir.exists() && dir.isDirectory()) {
            String[] children = dir.list();

            for (int i = 0; i < children.length; i++) {
                boolean success = deleteDir(new File(dir, children[i]));
                if (!success) {
                    return false;
                }
            }
        }

        return dir.delete();
    }

    /**
     * Delete a file
     *
     * @param file
     * @return
     */
    public static boolean deleteFile(String file) {
        File f = new File(file);
        if (f.exists() && f.isFile()) {
            return f.delete();
        }
        return true;
    }

    /**
     * Get a file list under a directory
     *
     * @param dir
     * @return
     */
    public static List<String> getFileList(String dir) {
        List<String> fileList = new ArrayList<String>();
        File _dir = new File(dir);
        File[] files = _dir.listFiles();

        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                if (files[i].isFile()) {
                    String fileName = files[i].getAbsolutePath();
                    fileList.add(fileName);
                }
            }
        }
        return fileList;
    }

    /**
     * Get file name list under a directory
     *
     * @param dir
     * @return
     */
    public static List<String> getFileNameList(String dir) {
        List<String> fileNameList = new ArrayList<String>();
        File _dir = new File(dir);

        File[] files = _dir.listFiles();

        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                if (files[i].isFile()) {
                    String fileName = files[i].getName();
                    fileNameList.add(fileName);
                }
            }
        }
        return fileNameList;
    }

    /**
     * Get directory name list of a directory
     *
     * @param dir
     * @return
     */
    public static List<String> getDirNameList(String dir) {
        List<String> dirNameList = new ArrayList<String>();
        File _dir = new File(dir);

        File[] files = _dir.listFiles();

        if (files != null) {
            for (int i = 0; i < files.length; i++) {
                if (files[i].isDirectory()) {
                    String dirName = files[i].getName();
                    dirNameList.add(dirName);
                }
            }
        }
        return dirNameList;
    }

    /**
     * Check if it is a valid file
     *
     * @param file
     * @return
     */
    public static boolean isFile(String file) {
        File f = new File(file);
        return f.exists() && f.isFile();
    }

    /**
     * Check if it is valid directory
     * @param file
     * @return
     */
    public static boolean isDir(String file) {
        File f = new File(file);
        return f.exists() && f.isDirectory();
    }

    /**
     * Get file name
     * @param file
     * @return
     */
    public static String getFileName(String file) {
        File f = new File(file);
        return f.getName();
    }
}
