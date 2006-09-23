package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import org.bouncycastle.mail.smime.SMIMEException;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.mail.MessagingException;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.util.encoders.Base64;

/**
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *      CertStore           certs...
 *      SMIMESignedGenerator  fact = new SMIMESignedGenerator();
 *
 *      fact.addSigner(privKey, cert, SMIMESignedGenerator.DIGEST_SHA1);
 *      fact.addCertificatesAndCRLs(certs);
 *
 *      MimeMultipart       smime = fact.generate(content, "BC");
 * </pre>
 * <p>
 * Note: if you are using this class with AS2 or some other protocol
 * that does not use 7bit as the default content transfer encoding you
 * will need to use the constructor that allows you to specify the default
 * content transfer encoding, such as "binary".
 * </p>
 */
public class SMIMESignedGenerator
    extends SMIMEGenerator
{
    public static final String  DIGEST_SHA1 = "1.3.14.3.2.26";
    public static final String  DIGEST_MD5 = "1.2.840.113549.2.5";
    public static final String  DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String  DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String  DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String  DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();
    
    public static final String  ENCRYPTION_RSA = "1.2.840.113549.1.1.1";
    public static final String  ENCRYPTION_DSA = "1.2.840.10040.4.3";

    private CMSSignedDataGenerator      fact;
    private String                      defaultContentTransferEncoding = "7bit";

    /**
     * base constructor - default content transfer encoding 7bit
     */
    public SMIMESignedGenerator()
    {
        fact = new CMSSignedDataGenerator();
    }

    /**
     * base constructor - default content transfer encoding explicitly set
     * 
     * @param defaultContentTransferEncoding new default to use.
     */
    public SMIMESignedGenerator(
        String defaultContentTransferEncoding)
    {
        fact = new CMSSignedDataGenerator();
        this.defaultContentTransferEncoding = defaultContentTransferEncoding;
    }

    /**
     * add a signer - no attributes other than the default ones will be
     * provided here.
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID)
        throws IllegalArgumentException
    {
        fact.addSigner(key, cert, digestOID);
    }

    /**
     * add a signer with extra signed/unsigned attributes.
     */
    public void addSigner(
        PrivateKey      key,
        X509Certificate cert,
        String          digestOID,
        AttributeTable  signedAttr,
        AttributeTable  unsignedAttr)
        throws IllegalArgumentException
    {
        fact.addSigner(key, cert, digestOID, signedAttr, unsignedAttr);
    }

    /**
     * add the certificates and CRLs contained in the given CertStore
     * to the pool that will be included in the encoded signature block.
     * <p>
     * Note: this assumes the CertStore will support null in the get
     * methods.
     */
    public void addCertificatesAndCRLs(
        CertStore               certStore)
        throws CertStoreException, SMIMEException
    {
        try
        {
            fact.addCertificatesAndCRLs(certStore);
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }
    }

    private void addHashHeader(
        StringBuffer     header,
        CMSSignedData    signedData)
    {
        int                 count = 0;
        
        //
        // build the hash header
        //
        Iterator   it = signedData.getSignerInfos().getSigners().iterator();
        Set        micAlgs = new HashSet();
        
        while (it.hasNext())
        {
            SignerInformation       signer = (SignerInformation)it.next();
            
            if (signer.getDigestAlgOID().equals(DIGEST_SHA1))
            {
                micAlgs.add("sha1");
            }
            else if (signer.getDigestAlgOID().equals(DIGEST_MD5))
            {
                micAlgs.add("md5");
            }
            else if (signer.getDigestAlgOID().equals(DIGEST_SHA224))
            {
                micAlgs.add("sha224");
            }
            else if (signer.getDigestAlgOID().equals(DIGEST_SHA256))
            {
                micAlgs.add("sha256");
            }
            else if (signer.getDigestAlgOID().equals(DIGEST_SHA384))
            {
                micAlgs.add("sha384");
            }
            else if (signer.getDigestAlgOID().equals(DIGEST_SHA512))
            {
                micAlgs.add("sha512");
            }
            else
            {
                header.append("unknown");
            }
        }
        
        it = micAlgs.iterator();
        
        while (it.hasNext())
        {
            String    alg = (String)it.next();

            if (count == 0)
            {
                if (micAlgs.size() != 1)
                {
                    header.append("; micalg=\"");
                }
                else
                {
                    header.append("; micalg=");
                }
            }
            else
            {
                header.append(',');
            }

            header.append(alg);

            count++;
        }

        if (count != 0)
        {
            if (micAlgs.size() != 1)
            {
                header.append('\"');
            }
        }
    }
    
    /**
     * at this point we expect our body part to be well defined.
     */
    private MimeMultipart make(
        MimeBodyPart    content,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        CMSSignedData       signedData;

        try
        {
            signedData = fact.generate(
                            new CMSProcessableBodyPartOutbound(content, defaultContentTransferEncoding), sigProvider);
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }

        //
        // build the header
        //
        StringBuffer        header = new StringBuffer(
                "signed; protocol=\"application/pkcs7-signature\"");
                
        addHashHeader(header, signedData);
        
        InternetHeaders sigHeader = new InternetHeaders();

        sigHeader.addHeader("Content-Type", "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data");
        sigHeader.addHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"");
        sigHeader.addHeader("Content-Description", "S/MIME Cryptographic Signature");

        try
        {
            MimeBodyPart    sig;
            
            if (useBase64)
            {
                sigHeader.addHeader("Content-Transfer-Encoding", "base64");

                sig = new MimeBodyPart(sigHeader, Base64.encode(signedData.getEncoded()));
            }
            else
            {
                sigHeader.addHeader("Content-Transfer-Encoding", encoding);

                sig = new MimeBodyPart(sigHeader, signedData.getEncoded());
            }

            MimeMultipart   mm = new MimeMultipart(header.toString());

            mm.addBodyPart(content);
            mm.addBodyPart(sig);

            return mm;
        }
        catch (IOException e)
        {
            throw new SMIMEException("exception encoding signature.", e);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
    }

    /**
     * at this point we expect our body part to be well defined - generate with data in the signature
     */
    private MimeBodyPart makeEncapsulated(
        MimeBodyPart    content,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        CMSSignedData       signedData;

        try
        {
            signedData = fact.generate(
                            new CMSProcessableBodyPart(content), true, sigProvider);
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }

        //
        // build the header
        //
        InternetHeaders sigHeader = new InternetHeaders();

        sigHeader.addHeader("Content-Type", "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data");
        sigHeader.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
        sigHeader.addHeader("Content-Description", "S/MIME Cryptographic Signed Data");

        try
        {
            MimeBodyPart    sig;
            
            if (useBase64)
            {
                sigHeader.addHeader("Content-Transfer-Encoding", "base64");

                sig = new MimeBodyPart(sigHeader, Base64.encode(signedData.getEncoded()));
            }
            else
            {
                sigHeader.addHeader("Content-Transfer-Encoding", encoding);

                sig = new MimeBodyPart(sigHeader, signedData.getEncoded());
            }

            return sig;
        }
        catch (IOException e)
        {
            throw new SMIMEException("exception encoding signature.", e);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting multi-part together.", e);
        }
    }

    /**
     * generate a signed object that contains an SMIME Signed Multipart
     * object using the given provider.
     */
    public MimeMultipart generate(
        MimeBodyPart    content,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return make(makeContentBodyPart(content), sigProvider);
    }

    /**
     * generate a signed object that contains an SMIME Signed Multipart
     * object using the given provider from the given MimeMessage
     */
    public MimeMultipart generate(
        MimeMessage     message,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }

        return make(makeContentBodyPart(message), sigProvider);
    }

    /**
     * generate a signed message with encapsulated content
     * <p>
     * Note: doing this is strongly <b>not</b> recommended as it means a
     * recipient of the message will have to be able to read the signature to read the 
     * message.
     */
    public MimeBodyPart generateEncapsulated(
        MimeBodyPart    content,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        return makeEncapsulated(makeContentBodyPart(content), sigProvider);
    }

    /**
     * generate a signed object that contains an SMIME Signed Multipart
     * object using the given provider from the given MimeMessage.
     * <p>
     * Note: doing this is strongly <b>not</b> recommended as it means a
     * recipient of the message will have to be able to read the signature to read the 
     * message.
     */
    public MimeBodyPart generateEncapsulated(
        MimeMessage     message,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, SMIMEException
    {
        try
        {
            message.saveChanges();      // make sure we're up to date.
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("unable to save message", e);
        }

        return makeEncapsulated(makeContentBodyPart(message), sigProvider);
    }
    
    /**
     * Creates a certificate management message which is like a signed message with no content
     * or signers but that still carries certificates and CRLs.
     * 
     * @return a MimeBodyPart containing the certs and CRLs.
     */
    public MimeBodyPart generateCertificateManagement(
       String provider) 
       throws SMIMEException, NoSuchProviderException
    {
        CMSSignedData signedData = null;
        
        try
        {
            signedData = fact.generate(null, false, provider);
        }
        catch (CMSException e)
        {
            throw new SMIMEException(e.getMessage(), e.getUnderlyingException());
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new SMIMEException("NoSuchAlgorithmException: " + e.getMessage(), e);
        }
        
        //
        // build the header
        //
        InternetHeaders sigHeader = new InternetHeaders();

        sigHeader.addHeader("Content-Type", "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only");
        sigHeader.addHeader("Content-Disposition", "attachment; filename=\"smime.p7c\"");
        sigHeader.addHeader("Content-Description", "S/MIME Certificate Management Message");

        try
        {
            MimeBodyPart    sig;
            
            if (useBase64)
            {
                sigHeader.addHeader("Content-Transfer-Encoding", "base64");

                sig = new MimeBodyPart(sigHeader, Base64.encode(signedData.getEncoded()));
            }
            else
            {
                sigHeader.addHeader("Content-Transfer-Encoding", encoding);

                sig = new MimeBodyPart(sigHeader, signedData.getEncoded());
            }

            return sig;
        }
        catch (IOException e)
        {
            throw new SMIMEException("exception encoding signature.", e);
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting body part together.", e);
        }
    }
}
