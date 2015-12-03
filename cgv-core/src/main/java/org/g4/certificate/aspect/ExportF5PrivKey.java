package org.g4.certificate.aspect;

import org.g4.certificate.utilities.ExportPriv;

/**
 * This is used to export private key of F5 keystore encoded by base64
 *
 * @author Johnson Jiang
 * @version 1.0
 */
public class ExportF5PrivKey implements CommandAspect {
    @Override
    public void beforeCommand(Object... obj) {
        //do nothing in this case
    }

    @Override
    public void afterCommand(Object... obj) {
        ExportPriv.export((String) obj[0], (String) obj[1], (String) obj[2], (String) obj[3]);
    }
}
