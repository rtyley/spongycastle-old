package org.bouncycastle.jce.provider.test;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.test.rsa3.RSA3CertTest;
import org.bouncycastle.util.test.SimpleTestResult;

import junit.framework.*;

public class AllTests
    extends TestCase
{
    public void testJCE()
    {   
        org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;
        
        for (int i = 0; i != tests.length; i++)
        {
            SimpleTestResult  result = (SimpleTestResult)tests[i].perform();
            
            if (!result.isSuccessful())
            {
                fail(result.toString());
            }
        }
    }
    
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCE Tests");
        
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());  
        }
        
        suite.addTestSuite(RSA3CertTest.class);
        suite.addTestSuite(AllTests.class);
        
        return suite;
    }
}
