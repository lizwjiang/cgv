package org.g4.certificate.handler;

import org.g4.certificate.aspect.CommandAspect;
import org.g4.certificate.bean.CommandBean;
import org.g4.certificate.exception.CommandExecutionException;
import org.g4.certificate.facade.CertLogger;
import org.g4.certificate.parser.CertGenParamParser;
import org.g4.certificate.utilities.CertParamTemplate;
import org.g4.certificate.utilities.CertUtil;
import org.g4.certificate.utilities.ExceptionUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Execute commands that are used to generate certificates for TSO, Apache and F5.
 *
 * @author Johnson Jiang
 * @version 1.0
 * @since 1.0
 */
public class CertificateExecutor {
    static CertLogger logger = CertLogger.getLogger(CertificateExecutor.class.getName());

    /**
     * Execute commands to generate certificates.
     *
     * @param commandList command list
     * @param ph          if JRE home is specified, use the keytool under it.
     *                    otherwise use the one under the JRE home configured in system environment variables
     */
    public static void execCommand(List<CommandBean> commandList, CertGenParamParser ph) {
        List<String> pbParamList = new ArrayList<String>();
        ProcessBuilder pb = new ProcessBuilder(pbParamList);
        pb.redirectErrorStream(true);

        for (CommandBean commBean : commandList) {
            pbParamList.clear();

            if (!CertUtil.isNull(commBean.getMessage()))
                logger.printToConsole(commBean.getMessage());

            CommandAspect ca = commBean.getCommandAspect();
            if (ca != null)
                ca.beforeCommand(commBean.getParams4CommandAspect());

            String[] commandArray = commBean.getCommand();
            for (int i = 0; i < commandArray.length; i++) {
                if (i == 0 && commandArray[0].equalsIgnoreCase(CertParamTemplate.CERT_KEYTOOL_COMMAND)) {
                    pbParamList.add(ph.getJREHome() + CertParamTemplate.JRE_BIN_PATH + CertParamTemplate.CERT_SLASH + commandArray[i]);
                } else {
                    pbParamList.add(commandArray[i]);
                }
            }

            CertUtil.printCertCommand(pbParamList);

            Process p = null;
            try {
                p = pb.command(pbParamList).start();
                int waitValue = p.waitFor();

                if (waitValue != 0 && p.exitValue() != 0) {
                    SMCertExceptionHandler.handleException(
                            new CommandExecutionException("Fail to execute the command : " + CertUtil.getCommandStr(pbParamList))
                    );
                }

            } catch (IOException e) {
                SMCertExceptionHandler.handleException(e, "Error happens when executing command : " + CertUtil.getCommandStr(pbParamList));
            } catch (InterruptedException e) {
                SMCertExceptionHandler.handleException(e, "Error happens when the command is being executed and the process is waiting");
            }
            if (p != null) {
                p.destroy();
            }

            if (ca != null)
                ca.afterCommand(commBean.getParams4CommandAspect());
        }
    }

}
