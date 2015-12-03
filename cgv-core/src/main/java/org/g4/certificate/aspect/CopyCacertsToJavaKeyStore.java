package org.g4.certificate.aspect;

import org.g4.certificate.exception.CGVRuntimeException;
import org.g4.certificate.utilities.CertExceptionHandler;
import org.g4.certificate.utilities.FileUtil;

/**
 * After self-signed CA is imported Java key store called cacerts in temp folder,
 * the modified cacerts needs to replace the one in JRE folder.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CopyCacertsToJavaKeyStore implements CommandAspect {
    @Override
    public void beforeCommand(Object... obj) {
        //do nothing in this case
    }

    @Override
    public void afterCommand(Object... obj) {
        boolean rtn = FileUtil.createFile((String) obj[0], (String) obj[1]);
        if (!rtn) {
            CertExceptionHandler.handleException(
                    new CGVRuntimeException("Fail to overwrite " + obj[0] + " with " + obj[1])
            );
        }
    }
}
