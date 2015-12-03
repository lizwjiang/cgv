package org.g4.certificate;


import org.junit.runner.JUnitCore;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

/**
 * Create Junit test suite to run all the test classes
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
@RunWith(Suite.class)
@Suite.SuiteClasses({
        org.g4.certificate.utilities.CertUtilTest.class,
        org.g4.certificate.utilities.FileUtilTest.class,
        org.g4.certificate.utilities.JUnitUtilTest.class,
        org.g4.certificate.utilities.PropertiesAnalyzerTest.class,

        org.g4.certificate.aspect.CopyCacertToJavaKeyStoreTest.class,
        org.g4.certificate.command.KeyToolCommandTest.class,
        org.g4.certificate.command.OpenSSLCommandTest.class,

        org.g4.certificate.checker.PropsRuleCheckerTest.class
})
public class AllUnitTests {
    public static void main(String[] args) {
        JUnitCore.main("org.g4.certificate.AllUnitTests");
    }
}
