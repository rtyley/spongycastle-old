package org.bouncycastle.asn1.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

public class X509NameTest
    implements Test
{
   String[] subjects =
   {
       "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au,E=webmaster@connect4.com.au",
       "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Certificate Authority,CN=Connect 4 CA,E=webmaster@connect4.com.au",
       "C=AU,ST=QLD,CN=SSLeay/rsa test cert",
       "C=US,O=National Aeronautics and Space Administration,SN=16+CN=Steve Schoch",
       "E=cooke@issl.atl.hp.com,C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke",
       "O=Sun Microsystems Inc,CN=store.sun.com",
       "unstructuredAddress=192.168.1.33,unstructuredName=pixfirewall.ciscopix.com,CN=pixfirewall.ciscopix.com"
    };

    public String getName()
    {
        return "X509Name";
    }
    
    private static X509Name fromBytes(
        byte[]  bytes) 
        throws IOException
    {
        return X509Name.getInstance(new ASN1InputStream(new ByteArrayInputStream(bytes)).readObject());
    }
    
    public TestResult perform()
    {
        Hashtable                   attrs = new Hashtable();

        attrs.put(X509Name.C, "AU");
        attrs.put(X509Name.O, "The Legion of the Bouncy Castle");
        attrs.put(X509Name.L, "Melbourne");
        attrs.put(X509Name.ST, "Victoria");
        attrs.put(X509Name.E, "feedback-crypto@bouncycastle.org");

        X509Name    name1 = new X509Name(attrs);

        if (!name1.equals(name1))
        {
            return new SimpleTestResult(false, getName() + ": Failed same object test");
        }

        X509Name    name2 = new X509Name(attrs);

        if (!name1.equals(name2))
        {
            return new SimpleTestResult(false, getName() + ": Failed same name test");
        }

        Vector  ord1 = new Vector();

        ord1.addElement(X509Name.C);
        ord1.addElement(X509Name.O);
        ord1.addElement(X509Name.L);
        ord1.addElement(X509Name.ST);
        ord1.addElement(X509Name.E);

        Vector  ord2 = new Vector();

        ord2.addElement(X509Name.E);
        ord2.addElement(X509Name.ST);
        ord2.addElement(X509Name.L);
        ord2.addElement(X509Name.O);
        ord2.addElement(X509Name.C);

        name1 = new X509Name(ord1, attrs);
        name2 = new X509Name(ord2, attrs);

        if (!name1.equals(name2))
        {
            return new SimpleTestResult(false, getName() + ": Failed reverse name test");
        }

        ord2 = new Vector();

        ord2.addElement(X509Name.ST);
        ord2.addElement(X509Name.ST);
        ord2.addElement(X509Name.L);
        ord2.addElement(X509Name.O);
        ord2.addElement(X509Name.C);

        name1 = new X509Name(ord1, attrs);
        name2 = new X509Name(ord2, attrs);

        if (name1.equals(name2))
        {
            return new SimpleTestResult(false, getName() + ": Failed different name test");
        }

        ord2 = new Vector();

        ord2.addElement(X509Name.ST);
        ord2.addElement(X509Name.L);
        ord2.addElement(X509Name.O);
        ord2.addElement(X509Name.C);

        name1 = new X509Name(ord1, attrs);
        name2 = new X509Name(ord2, attrs);

        if (name1.equals(name2))
        {
            return new SimpleTestResult(false, getName() + ": Failed subset name test");
        }
        
        //
        // composite test
        //
        try
        {
            byte[]  enc = Hex.decode("305e310b300906035504060c02415531283026060355040a0c1f546865204c6567696f6e206f662074686520426f756e637920436173746c653125301006035504070c094d656c626f75726e653011060355040b0c0a4173636f742056616c65");
            
            ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(enc));
            
            X509Name    n = X509Name.getInstance(aIn.readObject());
            
            if (!n.toString().equals("C=AU,O=The Legion of the Bouncy Castle,L=Melbourne+OU=Ascot Vale"))
            {
                return new SimpleTestResult(false, getName() + ": Failed composite to string test");
            }
            
            n = new X509Name("C=AU, O=The Legion of the Bouncy Castle, L=Melbourne + OU=Ascot Vale");
            
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);
            
            aOut.writeObject(n);
            
            byte[]  enc2 = bOut.toByteArray();

            if (!Arrays.areEqual(enc, enc2))
            {
                return new SimpleTestResult(false, getName() + ": Failed composite string to encoding test");
            }

            //
            // general subjects test
            //
            for (int i = 0; i != subjects.length; i++)
            {
                X509Name    name = new X509Name(subjects[i]);

                bOut = new ByteArrayOutputStream();
                aOut = new ASN1OutputStream(bOut);
            
                aOut.writeObject(name);

                aIn = new ASN1InputStream(new ByteArrayInputStream(bOut.toByteArray()));

                name = X509Name.getInstance(aIn.readObject());

                if (!name.toString().equals(subjects[i]))
                {
                    return new SimpleTestResult(false, getName() + ": failed regeneration test " + i);
                }
            }

            //
            // sort test
            //
            X509Name unsorted = new X509Name("SN=BBB + CN=AA");

            if (!fromBytes(unsorted.getEncoded()).toString().equals("CN=AA+SN=BBB"))
            {
                return new SimpleTestResult(false, getName() + ": failed sort test 1");
            }

            unsorted = new X509Name("CN=AA + SN=BBB");

            if (!fromBytes(unsorted.getEncoded()).toString().equals("CN=AA+SN=BBB"))
            {
                return new SimpleTestResult(false, getName() + ": failed sort test 2");
            }

            unsorted = new X509Name("SN=B + CN=AA");

            if (!fromBytes(unsorted.getEncoded()).toString().equals("SN=B+CN=AA"))
            {
                return new SimpleTestResult(false, getName() + ": failed sort test 3");
            }
            
            unsorted = new X509Name("CN=AA + SN=B");

            if (!fromBytes(unsorted.getEncoded()).toString().equals("SN=B+CN=AA"))
            {
                return new SimpleTestResult(false, getName() + ": failed sort test 4");
            }
            
            //
            // this is contrived but it checks sorting of sets with equal elements
            //
            unsorted = new X509Name("CN=AA + CN=AA + CN=AA");
            
            // 
            // tagging test - only works if CHOICE implemented
            //
            /*
            ASN1TaggedObject tag = new DERTaggedObject(false, 1, new X509Name("CN=AA"));
            
            if (!tag.isExplicit())
            {
                return new SimpleTestResult(false, getName() + ": failed to explicitly tag CHOICE object");
            }
            
            X509Name name = X509Name.getInstance(tag, false);
            
            if (!name.equals(new X509Name("CN=AA")))
            {
                return new SimpleTestResult(false, getName() + ": failed to recover tagged name");
            }
            */

        
        
            DERUTF8String testString = new DERUTF8String("The Legion of the Bouncy Castle");
            byte[] encodedBytes = testString.getEncoded();
            byte[] hexEncodedBytes = Hex.encode(encodedBytes);
            String hexEncodedString = "#" + new String(hexEncodedBytes);

            DERUTF8String converted = (DERUTF8String)
                new X509DefaultEntryConverter().getConvertedValue(
                    X509Name.L , hexEncodedString);

            if (!converted.equals(testString))
            {
                return new SimpleTestResult(false, getName() + ": failed X509DefaultEntryConverter test");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception " + e.getMessage(), e);
        }

        return new SimpleTestResult(true, getName() + ": Okay");
    }

    public static void main(
        String[]    args)
    {
        Test    test = new X509NameTest();

        TestResult  result = test.perform();

        System.out.println(result);
    }
}
