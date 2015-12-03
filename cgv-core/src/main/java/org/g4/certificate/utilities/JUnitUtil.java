package org.g4.certificate.utilities;

import java.lang.reflect.Method;

/**
 * The helper utility for unit test
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class JUnitUtil {

    public static Object getTestResult(Object obj, String method, Class[] args, Object[] values) {
        Object rtnObj = null;
        try {
            Method m = obj.getClass().getDeclaredMethod(method, args);
            m.setAccessible(true);
            rtnObj = m.invoke(obj, values);
            m.setAccessible(false);
        } catch (Exception e) {
            CertExceptionHandler.handleException(e, "Error happens when calling the " + method + " method of " + obj.getClass().getName());
        }

        return rtnObj;
    }

    public static Object getTestResult(Object obj, String method) {
        return getTestResult(obj, method, null, null);
    }

}
