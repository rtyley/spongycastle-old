package org.bouncycastle.openssl.test;

import java.io.*;
import java.security.*;
import java.security.interfaces.*;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.util.test.SimpleTestResult;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * basic class for reading test.pem - the password is "secret"
 */
public class ReaderTest
    implements Test
{
    private static class Password
        implements PasswordFinder
    {
        char[]  password;

        Password(
            char[] word)
        {
            this.password = word;
        }

        public char[] getPassword()
        {
            return password;
        }
    }

    public String getName()
    {
        return "PEMReaderTest";
    }

    public TestResult perform()
    {
        Reader          fRd =new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("test.pem")));
        PasswordFinder  pGet = new Password("secret".toCharArray());
        PEMReader       pemRd = new PEMReader(fRd, pGet);
        Object          o;

        try
        {
            while ((o = pemRd.readObject()) != null)
            {
                if (o instanceof KeyPair)
                {
                    KeyPair     pair = (KeyPair)o;
            
                    //System.out.println(pair.getPublic());
                    //System.out.println(pair.getPrivate());
                }
                else
                {
                    //System.out.println(o.toString());
                }
            }
            
            //
            // pkcs 7 data
            //
            fRd =new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("pkcs7.pem")));
            pemRd = new PEMReader(fRd);
            
            ContentInfo d = (ContentInfo)pemRd.readObject();    
                
            if (!d.getContentType().equals(CMSObjectIdentifiers.envelopedData))
            {
                return new SimpleTestResult(false, getName() + ": failed envelopedData check");
            }
            
            //
            // writer/reader test
            //
            ByteArrayOutputStream bOut = new ByteArrayOutputStream();
            PEMWriter             pWrt = new PEMWriter(new OutputStreamWriter(bOut));
            KeyPairGenerator      kpGen = KeyPairGenerator.getInstance("RSA", "BC");
            KeyPair               pair = kpGen.generateKeyPair();
            
            pWrt.writeObject(pair.getPublic());
            
            pWrt.close();
            
            pemRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
            
            RSAPublicKey k = (RSAPublicKey)pemRd.readObject();
            if (!k.equals(pair.getPublic()))
            {
                return new SimpleTestResult(false, getName() + ": Failed key read");
            }
        }
        catch (Exception e)
        {
            return new SimpleTestResult(false, getName() + ": exception - " + e.toString(), e);
        }
        
        return new SimpleTestResult(true, getName() + ": Okay");
    }
    
    public static void main(
        String[]  args)
        throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        Test            test = new ReaderTest();
        TestResult      result = test.perform();

        System.out.println(result.toString());
    }
}
