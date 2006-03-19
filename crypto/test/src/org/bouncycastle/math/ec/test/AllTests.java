package org.bouncycastle.math.ec.test;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AllTests 
{
    public static void main (String[] args) 
        throws Exception
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite() 
        throws Exception
    {   
        TestSuite suite = new TestSuite("EC Math tests");
        
        suite.addTest(PointCompressionTest.suite());
        suite.addTest(ECPointF2mTest.suite());
        
        return suite;
    }
}
