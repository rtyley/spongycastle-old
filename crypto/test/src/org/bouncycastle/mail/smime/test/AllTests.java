package org.bouncycastle.mail.smime.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests
{
    public static void main (String[] args)
        throws Exception
    {
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
