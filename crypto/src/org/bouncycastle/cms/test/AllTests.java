package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests {
    
    public static void main (String[] args) {
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
