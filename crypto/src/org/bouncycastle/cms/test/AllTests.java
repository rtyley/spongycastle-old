package org.bouncycastle.cms.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests {
    
    public static void main (String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        junit.textui.TestRunner.run (suite());
    }
    
    public static Test suite() {
        TestSuite suite= new TestSuite("CMS tests");
        suite.addTest(org.bouncycastle.cms.test.SignedDataTest.suite());
        suite.addTest(org.bouncycastle.cms.test.EnvelopedDataTest.suite());
        suite.addTest(org.bouncycastle.cms.test.CompressedDataTest.suite());
        return suite;
    }
}
