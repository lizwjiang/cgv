package org.g4.certificate.utilities;

/**
 * Enum object that should have different types of data
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class ParameterType {

    public enum Protocol {
        SSL, //Supports some version of SSL; may support other versions
        SSLv2, //Supports SSL version 2 or later; may support other versions
        SSLv3, //Supports SSL version 3; may support other versions
        TLS, //Supports some version of TLS; may support other versions
        TLSv1, //Supports RFC 2246: TLS version 1.0 ; may support other versions
        TLSv1_1, //Supports RFC 4346: TLS version 1.1 ; may support other versions
        TLSv1_2;  //Supports RFC 5246: TLS version 1.2 ; may support other versions

        @Override
        public String toString() {
            switch (this) {
                case TLSv1_1:
                    return "TLSv1.1";
                case TLSv1_2:
                    return "TLSv1.2";
            }
            return this.name();
        }
    }

    public enum KeyStore {
        JCEKS,   //jceks 	The proprietary keystore implementation provided by the SunJCE provider.
        JKS,     //jks 	The proprietary keystore implementation provided by the SUN provider.
        PKCS12   //pkcs12 	The transfer syntax for personal identity information as defined in PKCS #12.
    }

    public enum Algorithm {
        SunX509,
        PKIX
    }

}
