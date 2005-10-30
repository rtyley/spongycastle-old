package org.bouncycastle.mail.smime.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestSuite;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AllTests
{
    public static void main (String[] args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite()
        throws Exception
    {
        TestSuite suite= new TestSuite("SMIME tests");

        suite.addTest(org.bouncycastle.mail.smime.test.SMIMESignedTest.suite());
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMEEnvelopedTest.suite());
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMECompressedTest.suite());
        suite.addTest(org.bouncycastle.mail.smime.test.SMIMEMiscTest.suite());
        return suite;
    }
}
