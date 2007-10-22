package org.bouncycastle.sasn1.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import junit.framework.TestCase;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.sasn1.Asn1InputStream;
import org.bouncycastle.sasn1.Asn1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;


/**
 * X.690 test example
 *
 * @deprecated obsolete test case
 */
public class OIDTest
    extends TestCase
{
    byte[]    req1 = Hex.decode("0603813403");
    byte[]    req2 = Hex.decode("06082A36FFFFFFDD6311");
    
    private void recodeCheck(
        String oid, 
        byte[] enc) 
        throws IOException
    {
        ByteArrayInputStream     bIn = new ByteArrayInputStream(enc);
        Asn1InputStream          aIn = new Asn1InputStream(bIn);

        Asn1ObjectIdentifier      o = new Asn1ObjectIdentifier(oid);
        Asn1ObjectIdentifier      encO = (Asn1ObjectIdentifier)aIn.readObject();
        
        if (!o.equals(encO))
        {
            fail("oid ID didn't match - got: " + o + " expected " + encO);
        }

        byte[]                    bytes = o.getEncoded();

        if (bytes.length != enc.length)
        {
            fail("failed length test");
        }

        for (int i = 0; i != enc.length; i++)
        {
            if (bytes[i] != enc[i])
            {
                fail("failed comparison test - got: " + new String(Hex.encode(enc)) + " expected " +  new String(Hex.encode(bytes)));
            }
        }
    }
    
    private void valueCheck(
        String  oid)
        throws IOException
    {
        Asn1ObjectIdentifier    o = new Asn1ObjectIdentifier(oid);
        ByteArrayInputStream    bIn = new ByteArrayInputStream(o.getEncoded());
        Asn1InputStream         aIn = new Asn1InputStream(bIn);
        
        o = (Asn1ObjectIdentifier)aIn.readObject();
        
        if (!o.toString().equals(oid))
        {
            fail("failed oid check for " + oid);
        }
    }
    
    public void testRecode()
        throws IOException
    {
        recodeCheck("2.100.3", req1);
        recodeCheck("1.2.54.34359733987.17", req2);
    }
    
    public void testValue()
        throws IOException
    {
        valueCheck(PKCSObjectIdentifiers.pkcs_9_at_contentType.getId());
        valueCheck("1.1.127.32512.8323072.2130706432.545460846592.139637976727552.35747322042253312.9151314442816847872");
        valueCheck("1.2.123.12345678901.1.1.1");
        valueCheck("2.25.196556539987194312349856245628873852187.1");
    }
}
