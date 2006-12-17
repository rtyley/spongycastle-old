package org.bouncycastle.cms.test;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

public class EnvelopedDataTest
    extends TestCase 
{
    private static String          _signDN;
    private static KeyPair         _signKP;  
    private static X509Certificate _signCert;

    private static String          _origDN;
    private static KeyPair         _origKP;
    private static X509Certificate _origCert;

    private static String          _reciDN;
    private static KeyPair         _reciKP;
    private static X509Certificate _reciCert;
    
    private static boolean         _initialised = false;

    private byte[] oldKEK = Base64.decode(
                          "MIAGCSqGSIb3DQEHA6CAMIACAQIxQaI/MD0CAQQwBwQFAQIDBAUwDQYJYIZIAWUDBAEFBQAEI"
                        + "Fi2eHTPM4bQSjP4DUeDzJZLpfemW2gF1SPq7ZPHJi1mMIAGCSqGSIb3DQEHATAUBggqhkiG9w"
                        + "0DBwQImtdGyUdGGt6ggAQYk9X9z01YFBkU7IlS3wmsKpm/zpZClTceAAAAAAAAAAAAAA==");

    private byte[] ecKeyAgreeMsg = Base64.decode(
         "MIAGCSqGSIb3DQEHA6CAMIACAQIxgcShgcECAQOgQ6FBMAsGByqGSM49AgEF"
         + "AAMyAAPdXlSTpub+qqno9hUGkUDl+S3/ABhPziIB5yGU4678tgOgU5CiKG9Z"
         + "kfnabIJ3nZYwGgYJK4EFEIZIPwACMA0GCWCGSAFlAwQBLQUAMFswWTAtMCgx"
         + "EzARBgNVBAMTCkFkbWluLU1EU0UxETAPBgNVBAoTCDRCQ1QtMklEAgEBBCi/"
         + "rJRLbFwEVW6PcLLmojjW9lI/xGD7CfZzXrqXFw8iHaf3hTRau1gYMIAGCSqG"
         + "SIb3DQEHATAdBglghkgBZQMEASoEEMtCnKKPwccmyrbgeSIlA3qggAQQDLw8"
         + "pNJR97bPpj6baG99bQQQwhEDsoj5Xg1oOxojHVcYzAAAAAAAAAAAAAA=");



    private byte[] ecKeyAgreeKey = Base64.decode(
        "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDC8vp7xVTbKSgYVU5Wc"
      + "hGkWbzaj+yUFETIWP1Dt7+WSpq3ikSPdl7PpHPqnPVZfoIWhZANiAgSYHTgxf+Dd"
      + "Tt84dUvuSKkFy3RhjxJmjwIscK6zbEUzKhcPQG2GHzXhWK5x1kov0I74XpGhVkya"
      + "ElH5K6SaOXiXAzcyNGggTOk4+ZFnz5Xl0pBje3zKxPhYu0SnCw7Pcqw=");

//                          "MIGkAgEBBDC8vp7xVTbKSgYVU5WchGkWbzaj+yUFETIWP1Dt7+WSpq3ikSPdl7Pp" +
//                              "HPqnPVZfoIWgBwYFK4EEACKhZANiAgSYHTgxf+DdTt84dUvuSKkFy3RhjxJmjwIs" +
//                              "cK6zbEUzKhcPQG2GHzXhWK5x1kov0I74XpGhVkyaElH5K6SaOXiXAzcyNGggTOk4" +
//                              "+ZFnz5Xl0pBje3zKxPhYu0SnCw7Pcqw=");

    public EnvelopedDataTest()
    {
    }

    private static void init()
        throws Exception
    {
        if (!_initialised)
        {
            _initialised = true;
            
            _signDN   = "O=Bouncy Castle, C=AU";
            _signKP   = CMSTestUtil.makeKeyPair();  
            _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            _origKP   = CMSTestUtil.makeKeyPair();
            _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            _reciKP   = CMSTestUtil.makeKeyPair();
            _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);      
        }
    }
    
    public static void main(
        String args[]) 
    {
        junit.textui.TestRunner.run(EnvelopedDataTest.class);
    }

    public static Test suite() 
        throws Exception
    {
        init();
        
        return new CMSTestSetup(new TestSuite(EnvelopedDataTest.class));
    }

    public void testKeyTrans()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();


        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransAES128()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES128_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransCAST5SunJCE()
        throws Exception
    {
        if (Security.getProvider("SunJCE") == null)
        {
            return;
        }
        
        String version = System.getProperty("java.version");
        if (version.startsWith("1.4") || version.startsWith("1.3"))
        {
            return;
        }
        
        byte[]          data     = "WallaWallaWashington".getBytes();
    
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
    
        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.CAST5_CBC, "SunJCE");
        RecipientInformationStore  recipients = ed.getRecipientInfos();
        
        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.CAST5_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();
    
            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "SunJCE");
    
            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTransAES192()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES192_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.AES192_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), PKCSObjectIdentifiers.rsaEncryption.getId());
            
            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransAES256()
        throws Exception
    {
        byte[]          data     = "WallaWallaWashington".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.AES256_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "2.16.840.1.101.3.4.1.42");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransRC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTrans128RC4()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.2.840.113549.3.4", 128, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.2.840.113549.3.4");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }
    
    public void testKeyTransODES()
        throws Exception
    {
        byte[]          data     = "WallaWallaBouncyCastle".getBytes();

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                "1.3.14.3.2.7", "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), "1.3.14.3.2.7");
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testKeyTransSmallAES()
        throws Exception
    {
        byte[]          data     = new byte[] { 0, 1, 2, 3 };

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        edGen.addKeyTransRecipient(_reciCert);

        CMSEnvelopedData ed = edGen.generate(
                              new CMSProcessableByteArray(data),
                              CMSEnvelopedDataGenerator.AES128_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(),
                                   CMSEnvelopedDataGenerator.AES128_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            byte[] recData = recipient.getContent(_reciKP.getPrivate(), "BC");
            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testDESKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeDesede192Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.9.16.3.6");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testErrorneousKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = new SecretKeySpec(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }, "AES");

        CMSEnvelopedData ed = new CMSEnvelopedData(oldKEK);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), NISTObjectIdentifiers.id_aes128_wrap.getId());

            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testAESKEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeAES192Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "2.16.840.1.101.3.4.1.25");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertEquals(true, Arrays.equals(data, recData));
        }
    }

    public void testRC2KEK()
        throws Exception
    {
        byte[]    data = "WallaWallaWashington".getBytes();
        SecretKey kek  = CMSTestUtil.makeRC2128Key();
        
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();

        byte[]  kekId = new byte[] { 1, 2, 3, 4, 5 };

        edGen.addKEKRecipient(kek, kekId);

        CMSEnvelopedData ed = edGen.generate(
                                new CMSProcessableByteArray(data),
                                CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals(ed.getEncryptionAlgOID(), CMSEnvelopedDataGenerator.DES_EDE3_CBC);
        
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals(recipient.getKeyEncryptionAlgOID(), "1.2.840.113549.1.9.16.3.7");
            
            byte[] recData = recipient.getContent(kek, "BC");

            assertTrue(Arrays.equals(data, recData));
        }
    }

   public void testECKeyAgree()
        throws Exception
    {
        byte[] data = Hex.decode("504b492d4320434d5320456e76656c6f706564446174612053616d706c65");

        CMSEnvelopedData ed = new CMSEnvelopedData(ecKeyAgreeMsg);

        RecipientInformationStore  recipients = ed.getRecipientInfos();

        Collection  c = recipients.getRecipients();
        Iterator    it = c.iterator();

        assertEquals("2.16.840.1.101.3.4.1.42", ed.getEncryptionAlgOID());

        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(ecKeyAgreeKey);
        KeyFactory            fact = KeyFactory.getInstance("ECDH", "BC");

        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();

            assertEquals("1.3.133.16.840.63.0.2", recipient.getKeyEncryptionAlgOID());

            byte[] recData = recipient.getContent(fact.generatePrivate(privSpec), "BC");

            assertTrue(Arrays.equals(data, recData));
        }
    }
}
