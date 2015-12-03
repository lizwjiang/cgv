package org.g4.certificate.aspect;


import org.junit.Test;

import static org.junit.Assert.fail;
/**
 * Unit test for CopyCacertToJavaKeyStore
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CopyCacertToJavaKeyStoreTest {
    @Test
    public void afterCommand(){
        Object[] objArray = new Object[]{"abc","123"};
        try{
            CopyCacertsToJavaKeyStore t = new  CopyCacertsToJavaKeyStore();
            t.afterCommand(objArray);
            fail("Excpetion should be thrown");
        }catch(Exception e){

        }
    }
}
