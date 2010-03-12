package org.bouncycastle.mail.smime.examples;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import javax.mail.Address;
import javax.mail.Message;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CollectionCertStoreParameters;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * a simple example that creates a single signed mail message.
 */
public class CreateSignedMail
{
    //
    // certificate serial number seed.
    //
    static int  serialNo = 1;

    static AuthorityKeyIdentifier createAuthorityKeyId(
        PublicKey pub) 
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());
        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
            (ASN1Sequence)new ASN1InputStream(bIn).readObject());

        return new AuthorityKeyIdentifier(info);
    }

    static SubjectKeyIdentifier createSubjectKeyId(
        PublicKey pub) 
        throws IOException
    {
        ByteArrayInputStream bIn = new ByteArrayInputStream(pub.getEncoded());

        SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
            (ASN1Sequence)new ASN1InputStream(bIn).readObject());

        return new SubjectKeyIdentifier(info);
    }

    /**
     * create a basic X509 certificate from the given keys
     */
    static X509Certificate makeCertificate(
        KeyPair subKP,
        String  subDN,
        KeyPair issKP,
        String  issDN) 
        throws GeneralSecurityException, IOException
    {
        X509Name   xName   = new X509Name(subDN);
        PublicKey  subPub  = subKP.getPublic();
        PrivateKey issPriv = issKP.getPrivate();
        PublicKey  issPub  = issKP.getPublic();
        
        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();
        
        v3CertGen.setSerialNumber(BigInteger.valueOf(serialNo++));
        v3CertGen.setIssuerDN(new X509Name(issDN));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100)));
        v3CertGen.setSubjectDN(new X509Name(subDN));
        v3CertGen.setPublicKey(subPub);
        v3CertGen.setSignatureAlgorithm("MD5WithRSAEncryption");

        v3CertGen.addExtension(
            X509Extensions.SubjectKeyIdentifier,
            false,
            createSubjectKeyId(subPub));

        v3CertGen.addExtension(
            X509Extensions.AuthorityKeyIdentifier,
            false,
            createAuthorityKeyId(issPub));

        return v3CertGen.generateX509Certificate(issPriv);
    }

    public static void main(
        String args[])
        throws Exception
    {
        //
        // set up our certs
        //
        KeyPairGenerator    kpg  = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024, new SecureRandom());

        //
        // cert that issued the signing certificate
        //
        String              signDN = "O=Bouncy Castle, C=AU";
        KeyPair             signKP = kpg.generateKeyPair();
        X509Certificate     signCert = makeCertificate(
                                        signKP, signDN, signKP, signDN);

        //
        // cert we sign against
        //
        String              origDN = "CN=Eric H. Echidna, E=eric@bouncycastle.org, O=Bouncy Castle, C=AU";
        KeyPair             origKP = kpg.generateKeyPair();
        X509Certificate     origCert = makeCertificate(
                                        origKP, origDN, signKP, signDN);

        List                certList = new ArrayList();

        certList.add(origCert);
        certList.add(signCert);

        //
        // create a CertStore containing the certificates we want carried
        // in the signature
        //
        CertStore           certsAndcrls = CertStore.getInstance(
                                "Collection",
                                new CollectionCertStoreParameters(certList), "BC");

        //
        // create some smime capabilities in case someone wants to respond
        //
        ASN1EncodableVector         signedAttrs = new ASN1EncodableVector();
        SMIMECapabilityVector       caps = new SMIMECapabilityVector();

        caps.addCapability(SMIMECapability.dES_EDE3_CBC);
        caps.addCapability(SMIMECapability.rC2_CBC, 128);
        caps.addCapability(SMIMECapability.dES_CBC);

        signedAttrs.add(new SMIMECapabilitiesAttribute(caps));

        //
        // add an encryption key preference for encrypted responses -
        // normally this would be different from the signing certificate...
        //
        IssuerAndSerialNumber   issAndSer = new IssuerAndSerialNumber(
                new X509Name(signDN), origCert.getSerialNumber());

        signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(issAndSer));

        //
        // create the generator for creating an smime/signed message
        //
        SMIMESignedGenerator gen = new SMIMESignedGenerator();

        //
        // add a signer to the generator - this specifies we are using SHA1 and
        // adding the smime attributes above to the signed attributes that
        // will be generated as part of the signature. The encryption algorithm
        // used is taken from the key - in this RSA with PKCS1Padding
        //
        gen.addSigner(origKP.getPrivate(), origCert, SMIMESignedGenerator.DIGEST_SHA1, new AttributeTable(signedAttrs), null);

        //
        // add our pool of certs and cerls (if any) to go with the signature
        //
        gen.addCertificatesAndCRLs(certsAndcrls);

        //
        // create the base for our message
        //
        MimeBodyPart    msg = new MimeBodyPart();

        msg.setText("Hello world!");

        //
        // extract the multipart object from the SMIMESigned object.
        //
        MimeMultipart mm = gen.generate(msg, "BC");

        //
        // Get a Session object and create the mail message
        //
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address fromUser = new InternetAddress("\"Eric H. Echidna\"<eric@bouncycastle.org>");
        Address toUser = new InternetAddress("example@bouncycastle.org");

        MimeMessage body = new MimeMessage(session);
        body.setFrom(fromUser);
        body.setRecipient(Message.RecipientType.TO, toUser);
        body.setSubject("example signed message");
        body.setContent(mm, mm.getContentType());
        body.saveChanges();

        body.writeTo(new FileOutputStream("signed.message"));
    }
}
