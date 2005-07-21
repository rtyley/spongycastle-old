package org.bouncycastle.cms.test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.crypto.SecretKey;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;

public class EnvelopedDataTest extends TestCase {

    /*
     *
     *  VARIABLES
     *
     */

    public boolean DEBUG = true;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public EnvelopedDataTest(String name) {
        super(name);
    }

    public static void main(String args[]) {
        junit.textui.TestRunner.run(EnvelopedDataTest.class);
    }

    public static Test suite() {
        return new CMSTestSetup(new TestSuite(EnvelopedDataTest.class));
    }

    public void log(Exception _ex) {
        if(DEBUG) {
            _ex.printStackTrace();
        }
    }

    public void log(String _msg) {
        if(DEBUG) {
            System.out.println(_msg);
        }
    }

    public void setUp() {

    }

    public void tearDown() {

    }

    /*
     *
     *  TESTS
     *
     */

    public void testKeyTrans()
    {
        try {
            byte[]          data     = "WallaWallaWashington".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testKeyTransAES128()
    {
        try {
            byte[]          data     = "WallaWallaWashington".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testKeyTransAES192()
    {
        try {
            byte[]          data     = "WallaWallaWashington".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testKeyTransAES256()
    {
        try {
            byte[]          data     = "WallaWallaWashington".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testKeyTransRC4()
    {
        try
        {
            byte[]          data     = "WallaWallaBouncyCastle".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    
    public void testKeyTrans128RC4()
    {
        try
        {
            byte[]          data     = "WallaWallaBouncyCastle".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
    public void testKeyTransODES()
    {
        try
        {
            byte[]          data     = "WallaWallaBouncyCastle".getBytes();

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testKeyTransSmallAES()
    {
        try
        {
            byte[]          data     = new byte[] { 0, 1, 2, 3 };

            String          _signDN   = "O=Bouncy Castle, C=AU";
            KeyPair         _signKP   = CMSTestUtil.makeKeyPair();  
            X509Certificate _signCert = CMSTestUtil.makeCertificate(_signKP, _signDN, _signKP, _signDN);

            String          _origDN   = "CN=Bob, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _origKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _origCert = CMSTestUtil.makeCertificate(_origKP, _origDN, _signKP, _signDN);

            String          _reciDN   = "CN=Doug, OU=Sales, O=Bouncy Castle, C=AU";
            KeyPair         _reciKP   = CMSTestUtil.makeKeyPair();
            X509Certificate _reciCert = CMSTestUtil.makeCertificate(_reciKP, _reciDN, _signKP, _signDN);
            
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
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void testDESKEK()
    {
        try {
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }
    
    public void testAESKEK()
    {
        try {
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
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testRC2KEK()
    {
        try {
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

                assertEquals(true, Arrays.equals(data, recData));
            }
            
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }
}
