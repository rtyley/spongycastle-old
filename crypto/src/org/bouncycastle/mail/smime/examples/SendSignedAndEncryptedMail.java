package org.bouncycastle.mail.smime.examples;

import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.util.Properties;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.activation.MailcapCommandMap;
import javax.activation.CommandMap;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.util.Strings;
import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.AttributeTable;

/**
 * Example that sends a signed and encrypted mail message.
 */
public class SendSignedAndEncryptedMail
{
    public static void main(String args[])
    {
        if (args.length != 5)
        {
            System.err
                    .println("usage: SendSignedAndEncryptedMail <pkcs12Keystore> <password> <keyalias> <smtp server> <email address>");
            System.exit(0);
        }

        try
        {
            MailcapCommandMap mailcap = (MailcapCommandMap)CommandMap
                    .getDefaultCommandMap();

            mailcap
                    .addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
            mailcap
                    .addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
            mailcap
                    .addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
            mailcap
                    .addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
            mailcap
                    .addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

            CommandMap.setDefaultCommandMap(mailcap);

            /* Add BC */
            Security.addProvider(new BouncyCastleProvider());

            /* Open the keystore */
            KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
            keystore.load(new FileInputStream(args[0]), args[1].toCharArray());
            Certificate[] chain = keystore.getCertificateChain(args[2]);

            /* Get the private key to sign the message with */
            PrivateKey privateKey = (PrivateKey)keystore.getKey(args[2],
                    args[1].toCharArray());
            if (privateKey == null)
            {
                throw new Exception("cannot find private key for alias: "
                        + args[2]);
            }

            /* Create the message to sign and encrypt */
            Properties props = System.getProperties();
            props.put("mail.smtp.host", args[3]);
            Session session = Session.getDefaultInstance(props, null);

            MimeMessage body = new MimeMessage(session);
            body.setFrom(new InternetAddress(args[4]));
            body.setRecipient(Message.RecipientType.TO, new InternetAddress(
                    args[4]));
            body.setSubject("example encrypted message");
            body.setContent("example encrypted message", "text/plain");
            body.saveChanges();

            /* Create the SMIMESignedGenerator */
            SMIMECapabilityVector capabilities = new SMIMECapabilityVector();
            capabilities.addCapability(SMIMECapability.dES_EDE3_CBC);
            capabilities.addCapability(SMIMECapability.rC2_CBC, 128);
            capabilities.addCapability(SMIMECapability.dES_CBC);

            ASN1EncodableVector attributes = new ASN1EncodableVector();
            attributes.add(new SMIMEEncryptionKeyPreferenceAttribute(
                    new IssuerAndSerialNumber(
                            new X509Name(((X509Certificate)chain[0])
                                    .getIssuerDN().getName()),
                            ((X509Certificate)chain[0]).getSerialNumber())));
            attributes.add(new SMIMECapabilitiesAttribute(capabilities));

            SMIMESignedGenerator signer = new SMIMESignedGenerator();
            signer
                    .addSigner(
                            privateKey,
                            (X509Certificate)chain[0],
                            "DSA".equals(privateKey.getAlgorithm()) ? SMIMESignedGenerator.DIGEST_SHA1
                                    : SMIMESignedGenerator.DIGEST_MD5,
                            new AttributeTable(attributes), null);

            /* Add the list of certs to the generator */
            List certList = new ArrayList();
            certList.add(chain[0]);
            CertStore certs = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(certList), "BC");
            signer.addCertificatesAndCRLs(certs);

            /* Sign the message */
            MimeMultipart mm = signer.generate(body, "BC");
            MimeMessage signedMessage = new MimeMessage(session);

            /* Set all original MIME headers in the signed message */
            Enumeration headers = body.getAllHeaderLines();
            while (headers.hasMoreElements())
            {
                signedMessage.addHeaderLine((String)headers.nextElement());
            }

            /* Set the content of the signed message */
            signedMessage.setContent(mm);
            signedMessage.saveChanges();

            /* Create the encrypter */
            SMIMEEnvelopedGenerator encrypter = new SMIMEEnvelopedGenerator();
            encrypter.addKeyTransRecipient((X509Certificate)chain[0]);

            /* Encrypt the message */
            MimeBodyPart encryptedPart = encrypter.generate(signedMessage,
                    SMIMEEnvelopedGenerator.RC2_CBC, "BC");

            /*
             * Create a new MimeMessage that contains the encrypted and signed
             * content
             */
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            encryptedPart.writeTo(out);

            MimeMessage encryptedMessage = new MimeMessage(session,
                    new ByteArrayInputStream(out.toByteArray()));

            /* Set all original MIME headers in the encrypted message */
            headers = body.getAllHeaderLines();
            while (headers.hasMoreElements())
            {
                String headerLine = (String)headers.nextElement();
                /*
                 * Make sure not to override any content-* headers from the
                 * original message
                 */
                if (!Strings.toLowerCase(headerLine).startsWith("content-"))
                {
                    encryptedMessage.addHeaderLine(headerLine);
                }
            }

            Transport.send(encryptedMessage);
        }
        catch (SMIMEException ex)
        {
            ex.getUnderlyingException().printStackTrace(System.err);
            ex.printStackTrace(System.err);
        }
        catch (Exception ex)
        {
            ex.printStackTrace(System.err);
        }
    }
}
