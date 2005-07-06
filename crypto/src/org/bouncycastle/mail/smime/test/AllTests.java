package org.bouncycastle.mail.smime.test;

import java.security.Security;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;

import junit.framework.Test;
import junit.framework.TestSuite;


public class AllTests {
    
    public static void main (String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        MailcapCommandMap _mailcap =
                           (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        _mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        _mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        _mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        _mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        _mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        CommandMap.setDefaultCommandMap(_mailcap);

        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite ( ) {
        TestSuite suite= new TestSuite("SMIME tests");
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMESignedTest.suite());
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMEEnvelopedTest.suite());
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMECompressedTest.suite());
        return suite;
    }
}
