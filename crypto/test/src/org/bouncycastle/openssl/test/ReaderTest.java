package org.bouncycastle.openssl.test;

import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.test.SimpleTest;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;

/**
 * basic class for reading test.pem - the password is "secret"
 */
public class ReaderTest
    extends SimpleTest
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

    public void performTest()
        throws Exception
    {
        Reader          fRd =new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("test.pem")));
        PasswordFinder  pGet = new Password("secret".toCharArray());
        PEMReader       pemRd = new PEMReader(fRd, pGet);
        Object          o;
        KeyPair         pair;

        while ((o = pemRd.readObject()) != null)
        {
            if (o instanceof KeyPair)
            {
                //pair = (KeyPair)o;
        
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
        fRd = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("pkcs7.pem")));
        pemRd = new PEMReader(fRd);
        
        ContentInfo d = (ContentInfo)pemRd.readObject();    
            
        if (!d.getContentType().equals(CMSObjectIdentifiers.envelopedData))
        {
            fail("failed envelopedData check");
        }

        //
        // ECKey
        //
        fRd = new BufferedReader(new InputStreamReader(this.getClass().getResourceAsStream("eckey.pem")));
        pemRd = new PEMReader(fRd);
        ECNamedCurveParameterSpec spec = (ECNamedCurveParameterSpec)pemRd.readObject();

        pair = (KeyPair)pemRd.readObject();
        Signature sgr = Signature.getInstance("ECDSA", "BC");

        sgr.initSign(pair.getPrivate());

        byte[] message = new byte[] { (byte)'a', (byte)'b', (byte)'c' };

        sgr.update(message);

        byte[]  sigBytes = sgr.sign();

        sgr.initVerify(pair.getPublic());

        sgr.update(message);

        if (!sgr.verify(sigBytes))
        {
            fail("EC verification failed");
        }

        if (!pair.getPublic().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on public");
        }

        if (!pair.getPrivate().getAlgorithm().equals("ECDSA"))
        {
            fail("wrong algorithm name on private");
        }

        //
        // writer/parser test
        //
        KeyPairGenerator      kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        
        pair = kpGen.generateKeyPair();
        
        keyPairTest("RSA", pair);
        
        kpGen = KeyPairGenerator.getInstance("DSA", "BC");
        kpGen.initialize(512, new SecureRandom());
        pair = kpGen.generateKeyPair();
        
        keyPairTest("DSA", pair);
        
        //
        // PKCS7
        //
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter             pWrt = new PEMWriter(new OutputStreamWriter(bOut));
        
        pWrt.writeObject(d);
        
        pWrt.close();
        
        pemRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
        d = (ContentInfo)pemRd.readObject();    
        
        if (!d.getContentType().equals(CMSObjectIdentifiers.envelopedData))
        {
            fail("failed envelopedData recode check");
        }
    }

    private void keyPairTest(
        String   name,
        KeyPair pair) 
        throws IOException
    {
        PEMReader pemRd;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter             pWrt = new PEMWriter(new OutputStreamWriter(bOut));
        
        pWrt.writeObject(pair.getPublic());
        
        pWrt.close();

        pemRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
        
        PublicKey k = (PublicKey)pemRd.readObject();
        if (!k.equals(pair.getPublic()))
        {
            fail("Failed public key read: " + name);
        }
        
        bOut = new ByteArrayOutputStream();
        pWrt = new PEMWriter(new OutputStreamWriter(bOut));
        
        pWrt.writeObject(pair.getPrivate());
        
        pWrt.close();
        
        pemRd = new PEMReader(new InputStreamReader(new ByteArrayInputStream(bOut.toByteArray())));
        
        KeyPair kPair = (KeyPair)pemRd.readObject();
        if (!kPair.getPrivate().equals(pair.getPrivate()))
        {
            fail("Failed private key read: " + name);
        }
        
        if (!kPair.getPublic().equals(pair.getPublic()))
        {
            fail("Failed private key public read: " + name);
        }
    }
    
    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new ReaderTest());
    }
}
