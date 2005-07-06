package org.bouncycastle.mail.smime.test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.Session;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class SMIMECompressedTest
    extends TestCase
{

    boolean DEBUG = true;

    MimeBodyPart    msg;

    String          signDN;
    KeyPair         signKP;
    X509Certificate signCert;

    String          origDN;
    KeyPair         origKP;
    X509Certificate origCert;

    String          reciDN;
    KeyPair         reciKP;
    X509Certificate reciCert;

    KeyPair         dsaSignKP;
    X509Certificate dsaSignCert;

    KeyPair         dsaOrigKP;
    X509Certificate dsaOrigCert;

    /*
     *
     *  INFRASTRUCTURE
     *
     */

    public SMIMECompressedTest(String name) {
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

        junit.textui.TestRunner.run(SMIMECompressedTest.class);
    }

    public static Test suite() {
        return new TestSuite(SMIMECompressedTest.class);
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

    public void setUp()
    {
        try
        {
            msg      = SMIMETestUtil.makeMimeBodyPart("Hello world!");

            signDN   = "O=Bouncy Castle, C=AU";
            signKP   = SMIMETestUtil.makeKeyPair();  
            signCert = SMIMETestUtil.makeCertificate(signKP, signDN, signKP, signDN);

            origDN   = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
            origKP   = SMIMETestUtil.makeKeyPair();
            origCert = SMIMETestUtil.makeCertificate(origKP, origDN, signKP, signDN);
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }

    public void tearDown() {

    }

    /*
     *
     *  TESTS
     *
     */

    /**
     * test compressing and uncompressing of a multipart-signed message.
     */
    public void testSHA1WithRSA()
    {
        try
        {
            ArrayList           certList = new ArrayList();

            certList.add(origCert);
            certList.add(signCert);

            CertStore           certs = CertStore.getInstance("Collection",
                                           new CollectionCertStoreParameters(certList), "BC");

            ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
            SMIMECapabilityVector       caps = new SMIMECapabilityVector();

            caps.addCapability(SMIMECapability.dES_EDE3_CBC);
            caps.addCapability(SMIMECapability.rC2_CBC, 128);
            caps.addCapability(SMIMECapability.dES_CBC);

            signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

            SMIMESignedGenerator gen = new SMIMESignedGenerator();

            gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

            gen.addCertificatesAndCRLs(certs);

            MimeMultipart smp = gen.generate(msg, "BC");

            String boundary = new ContentType(smp.getContentType()).getParameter("boundary");
            MimeMessage bp2 = new MimeMessage((Session)null);                          

            bp2.setContent(smp, smp.getContentType());

            bp2.saveChanges();

            SMIMECompressedGenerator    cgen = new SMIMECompressedGenerator();

            MimeBodyPart cbp = cgen.generate(bp2, SMIMECompressedGenerator.ZLIB);

            SMIMECompressed cm = new SMIMECompressed(cbp);

            MimeBodyPart  _res = (MimeBodyPart)smp.getBodyPart(0);
            
            SMIMESigned s = new SMIMESigned((MimeMultipart)SMIMEUtil.toMimeBodyPart(cm.getContent()).getContent());

            ByteArrayOutputStream _baos = new ByteArrayOutputStream();
            msg.writeTo(_baos);
            _baos.close();
            byte[] _msgBytes = _baos.toByteArray();
            _baos = new ByteArrayOutputStream();
            s.getContent().writeTo(_baos);
            _baos.close();
            byte[] _resBytes = _baos.toByteArray();
            
            assertEquals(true, Arrays.equals(_msgBytes, _resBytes));

            certs = s.getCertificatesAndCRLs("Collection", "BC");

            SignerInformationStore  signers = s.getSignerInfos();
            Collection              c = signers.getSigners();
            Iterator                it = c.iterator();

            while (it.hasNext())
            {
                SignerInformation   signer = (SignerInformation)it.next();
                Collection          certCollection = certs.getCertificates(signer.getSID());

                Iterator            certIt = certCollection.iterator();
                X509Certificate     cert = (X509Certificate)certIt.next();

                assertEquals(true, signer.verify(cert, "BC"));
            }
        }
        catch(Exception ex)
        {
            log(ex);
            fail();
        }
    }
}
