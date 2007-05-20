package org.bouncycastle.jce.provider.test;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.jce.provider.PKIXNameConstraints;
import org.bouncycastle.util.test.SimpleTest;

import java.security.cert.CertPathValidatorException;

public class PKIXNameConstraintsTest
    extends SimpleTest
{
    private static final String[] includedEmail =
    {
       "test@included.com"
    };

    private static final String[] excludedEmail =
    {
       "test@excluded.com"
    };

    private static final String[] testEmail =
    {
        "test@excluded.com",
        "test@included.com"
    };

    private static final String[] includedDNS =
    {
       "included.com"
    };

    private static final String[] excludedDNS =
    {
       "excluded.com"
    };

    private static final String[] testDNS =
    {
        "test@excluded.com",
        "test@included.com"
    };

    private static final String[] includedDN =
    {
       "CN=included.com"
    };

    private static final String[] excludedDN =
    {
       "CN=excluded.com"
    };

    private static final String[] testDN =
    {
        "CN=test@excluded.com",
        "CN=test@included.com"
    };

    private static final String[] includedURI =
    {
       "included.com"
    };

    private static final String[] excludedURI =
    {
       "excluded.com"
    };

    private static final String[] testURI =
    {
        "excluded.com",
        "included.com"
    };

    private final static byte[][] includedIP =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 192, (byte) 168, 1, 2, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 }
    };

    private final static byte[][] excludedIP =
    {
    { (byte) 193, (byte) 168, 2, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 },
    { (byte) 193, (byte) 168, 2, 2, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 0 }
    };

    private final static byte[][] testIP =
    {
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 2 },
    { (byte) 192, (byte) 168, 1, 1, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 3 }
    };

	public String getName()
	{
		return "PKIXNameConstraintsTest";
	}

	public void performTest() throws Exception
	{
        testConstraints(GeneralName.rfc822Name, testEmail, includedEmail, excludedEmail);
        testConstraints(GeneralName.dNSName, testDNS, includedDNS, excludedDNS);
        testConstraints(GeneralName.directoryName, testDN, includedDN, excludedDN);
        testConstraints(GeneralName.uniformResourceIdentifier, testURI, includedURI, excludedURI);
//        testConstraints(GeneralName.iPAddress, testIP, includedIP, excludedIP);
	}

    private void testConstraints(int nameType, String[] testNames, String[] included, String[] excluded)
        throws Exception
    {
        PKIXNameConstraints constraints = new PKIXNameConstraints();

        for (int i = 0; i != included.length; i++)
        {
            constraints.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, included[i])));
        }

        for (int i = 0; i != excluded.length; i++)
        {
            constraints.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, excluded[i])));
        }

        for (int i = 0; i != excluded.length; i++)
        {
            try
            {
                constraints.checkExcluded(new GeneralName(nameType, excluded[i]));
                fail("excluded name missed: " + nameType);
            }
            catch (CertPathValidatorException e)
            {
                // expected
            }
        }

        for (int i = 0; i != included.length; i++)
        {
            constraints.checkExcluded(new GeneralName(nameType, included[i]));
        }

        constraints.checkPermitted(new GeneralName(nameType, included[0]));
        
        try
        {
            constraints.checkPermitted(new GeneralName(nameType, excluded[0]));
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }
    }

    private void testConstraints(int nameType, byte[][] testNames, byte[][] included, byte[][] excluded)
        throws Exception
    {
        PKIXNameConstraints constraints = new PKIXNameConstraints();

        for (int i = 0; i != included.length; i++)
        {
            constraints.intersectPermittedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(included[i]))));
        }

        for (int i = 0; i != excluded.length; i++)
        {
            constraints.addExcludedSubtree(new GeneralSubtree(new GeneralName(nameType, new DEROctetString(excluded[i]))));
        }

        for (int i = 0; i != excluded.length; i++)
        {
            try
            {
                constraints.checkExcluded(new GeneralName(nameType, new DEROctetString(excluded[i])));
                fail("excluded name missed: " + nameType);
            }
            catch (CertPathValidatorException e)
            {
                // expected
            }
        }

        for (int i = 0; i != included.length; i++)
        {
            constraints.checkExcluded(new GeneralName(nameType, new DEROctetString(included[i])));
        }

        constraints.checkPermitted(new GeneralName(nameType, new DEROctetString(included[0])));

        try
        {
            constraints.checkPermitted(new GeneralName(nameType, new DEROctetString(excluded[0])));
        }
        catch (CertPathValidatorException e)
        {
            // expected
        }
    }

    public static void main(String[] args)
	{
		runTest(new PKIXNameConstraintsTest());
	}
}
