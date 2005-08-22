package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.internet.MimeBodyPart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.test.CMSTestUtil;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class SMIMEEnvelopedTest extends TestCase {

    /*
     *
     *  VARIABLES
     *
     */

    public boolean DEBUG = true;

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
    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMEEnvelopedTest(String name) {
        super(name);
    }

    public static void main(String args[]) {
        MailcapCommandMap _mailcap =
                           (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        _mailcap.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        _mailcap.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        _mailcap.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        _mailcap.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        _mailcap.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

        CommandMap.setDefaultCommandMap(_mailcap);

        junit.textui.TestRunner.run(SMIMEEnvelopedTest.class);
    }

    public static Test suite() 
        throws Exception {
        init();
        
        return new SMIMETestSetup(new TestSuite(SMIMEEnvelopedTest.class));
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

    public void testDESEDE3Encrypted()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
              
            gen.addKeyTransRecipient(_reciCert);
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //

            MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.DES_EDE3_CBC, "BC");

            SMIMEEnveloped       m = new SMIMEEnveloped(mp);
            RecipientId          recId = new RecipientId();

            recId.setSerialNumber(_reciCert.getSerialNumber());
            recId.setIssuer(_reciCert.getIssuerX500Principal().getEncoded());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation       recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testIDEAEncrypted()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
              
            gen.addKeyTransRecipient(_reciCert);
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //

            MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.IDEA_CBC, "BC");

            SMIMEEnveloped  m = new SMIMEEnveloped(mp);

            RecipientId     recId = new RecipientId();

            recId.setSerialNumber(_reciCert.getSerialNumber());
            recId.setIssuer(_reciCert.getIssuerX500Principal().getEncoded());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation       recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testRC2Encrypted()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
              
            gen.addKeyTransRecipient(_reciCert);
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //

            MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.RC2_CBC, "BC");

            SMIMEEnveloped  m = new SMIMEEnveloped(mp);

            RecipientId     recId = new RecipientId();

            recId.setSerialNumber(_reciCert.getSerialNumber());
            recId.setIssuer(_reciCert.getIssuerX500Principal().getEncoded());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation        recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testCASTEncrypted()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator  gen = new SMIMEEnvelopedGenerator();
              
            gen.addKeyTransRecipient(_reciCert);
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //

            MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.CAST5_CBC, "BC");

            SMIMEEnveloped  m = new SMIMEEnveloped(mp);

            RecipientId     recId = new RecipientId();

            recId.setSerialNumber(_reciCert.getSerialNumber());
            recId.setIssuer(_reciCert.getIssuerX500Principal().getEncoded());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation        recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testSubKeyId()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

            //
            // create a subject key id - this has to be done the same way as
            // it is done in the certificate associated with the private key
            //
            MessageDigest           dig = MessageDigest.getInstance("SHA1", "BC");
            dig.update(_reciCert.getPublicKey().getEncoded());

              
            gen.addKeyTransRecipient(_reciCert.getPublicKey(), dig.digest());
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //

            MimeBodyPart         mp = gen.generate(_msg, SMIMEEnvelopedGenerator.DES_EDE3_CBC, "BC");

            SMIMEEnveloped       m = new SMIMEEnveloped(mp);

            RecipientId          recId = new RecipientId();

            dig.update(_reciCert.getPublicKey().getEncoded());

            recId.setSubjectKeyIdentifier(dig.digest());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation       recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }

    public void testCapEncrypt()
    {
        try
        {
            MimeBodyPart    _msg      = SMIMETestUtil.makeMimeBodyPart("WallaWallaWashington");

            SMIMEEnvelopedGenerator   gen = new SMIMEEnvelopedGenerator();

            //
            // create a subject key id - this has to be done the same way as
            // it is done in the certificate associated with the private key
            //
            MessageDigest           dig = MessageDigest.getInstance("SHA1", "BC");
            dig.update(_reciCert.getPublicKey().getEncoded());

              
            gen.addKeyTransRecipient(_reciCert.getPublicKey(), dig.digest());
             
            //
            // generate a MimeBodyPart object which encapsulates the content
            // we want encrypted.
            //
            MimeBodyPart mp = gen.generate(_msg, SMIMEEnvelopedGenerator.RC2_CBC, 40, "BC");

            SMIMEEnveloped       m = new SMIMEEnveloped(mp);

            RecipientId          recId = new RecipientId();

            dig.update(_reciCert.getPublicKey().getEncoded());

            recId.setSubjectKeyIdentifier(dig.digest());

            RecipientInformationStore  recipients = m.getRecipientInfos();
            RecipientInformation       recipient = recipients.get(recId);

            MimeBodyPart    res = SMIMEUtil.toMimeBodyPart(recipient.getContent(_reciKP.getPrivate(), "BC"));

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            _msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            res.writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));
        }
        catch(Exception ex) {
            log(ex);
            fail();
        }
    }
}
