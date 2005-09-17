package org.bouncycastle.sasn1.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class RegressionTest
{
    public static void main(String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("ASN.1 tests");
        
        suite.addTestSuite(Asn1SequenceTest.class);
        suite.addTestSuite(OctetStringTest.class);
        
        return suite;
    }
}
