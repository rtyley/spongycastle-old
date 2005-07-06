package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * X.690 test example
 */
public class OIDTest
    implements Test
{
    byte[]    req = Hex.decode("0603813403");

    public String getName()
    {
        return "OID";
    }
    
    private TestResult valueCheck(
        String  oid)
        throws IOException
    {
        DERObjectIdentifier     o = new DERObjectIdentifier(oid);
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
        
        aOut.writeObject(o);
        
        ByteArrayInputStream    bIn = new ByteArrayInputStream(bOut.toByteArray());
        ASN1InputStream         aIn = new ASN1InputStream(bIn);
        
        o = (DERObjectIdentifier)aIn.readObject();
        
        if (!o.getId().equals(oid))
        {
            return new SimpleTestResult(false, getName() + ": failed oid check for " + oid);
        }
            
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public TestResult perform()
    {
        try
        {
            ByteArrayInputStream     bIn = new ByteArrayInputStream(req);
            ASN1InputStream          aIn = new ASN1InputStream(bIn);

            DERObjectIdentifier      o = new DERObjectIdentifier("2.100.3");

            ByteArrayOutputStream    bOut = new ByteArrayOutputStream();
            DEROutputStream          dOut = new DEROutputStream(bOut);

            dOut.writeObject(o);

            byte[]                    bytes = bOut.toByteArray();

            if (bytes.length != req.length)
            {
                return new SimpleTestResult(false, getName() + ": failed length test");
            }

            for (int i = 0; i != req.length; i++)
            {
                if (bytes[i] != req[i])
                {
                    return new SimpleTestResult(false, getName() + ": failed comparison test");
                }
            }
            
            TestResult res = valueCheck(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId());
            if (!res.isSuccessful())
            {
                return res;
            }
            
            res = valueCheck("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
            if (!res.isSuccessful())
            {
                return res;
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": Exception - " + e.toString());
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Test    test = new OIDTest();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
