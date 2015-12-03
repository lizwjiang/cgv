package org.g4.certificate.utilities;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

/**
 * A property file contains key and value. Usually the data will be analyzed and put into a <p>Map</p>
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class PropertiesAnalyzer {
    /**
     * Get all the properties from a file
     *
     * @param fileName
     * @return
     * @throws IOException
     */
    public static Properties getProperties(String fileName) throws IOException {
        InputStream is = new BufferedInputStream(new FileInputStream(fileName));

        return getProperties(is);
    }

    /**
     * Get all the proeperties from an input stream.
     * @param is
     * @return
     * @throws IOException
     */
    public static Properties getProperties(InputStream is) throws IOException{
        Properties p = new Properties();
        p.load(is);
        if(is !=null)
            is.close();

        return p;
    }

    /**
     * Get all the data from a property file and put them in a HashMap object
     *
     * @param fileName
     * @return
     */
    public static Map<String, String> convertProperties2Map(String fileName) {
        Properties p = null;

        try {
            p = getProperties(fileName);
        } catch (IOException ioe) {
            CertExceptionHandler.handleException(ioe,
                    "Error happens when loading data from property file : " + fileName);
        }
        Map<String, String> paramMap = new HashMap<String, String>();

        for (Iterator<Object> it = p.keySet().iterator(); it.hasNext(); ) {
            String key = (String) it.next();
            paramMap.put(key.trim(), p.getProperty(key).trim());
        }

        return paramMap;
    }

}
