package org.bouncycastle.mail.smime;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import org.bouncycastle.jce.cert.CertStore;
import org.bouncycastle.jce.cert.CertStoreException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataStreamGenerator;
import org.bouncycastle.mail.smime.util.CRLFOutputStream;

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
 * that does not use "7bit" as the default content transfer encoding you
 * will need to use the constructor that allows you to specify the default
 * content transfer encoding, such as "binary".
 * </p>
 */
public class SMIMESignedGenerator
    extends SMIMEGenerator
{
    static final String CERTIFICATE_MANAGEMENT_CONTENT = "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only";
    private static final String DETACHED_SIGNATURE_TYPE = "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
    private static final String ENCAPSULATED_SIGNED_CONTENT_TYPE = "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data";
    public static final String  DIGEST_SHA1 = "1.3.14.3.2.26";
    public static final String  DIGEST_MD5 = "1.2.840.113549.2.5";
    public static final String  DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String  DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String  DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String  DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();

    public static final String  ENCRYPTION_RSA = "1.2.840.113549.1.1.1";
    public static final String  ENCRYPTION_DSA = "1.2.840.10040.4.3";

    private final String        _defaultContentTransferEncoding;

    private List                _certStores = new ArrayList();
    private List                _signers = new ArrayList();
    
    static
    {
        MailcapCommandMap mc = (MailcapCommandMap)CommandMap.getDefaultCommandMap();

        mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
        mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
        mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
        mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
        mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");
        
        CommandMap.setDefaultCommandMap(mc);
    }

    /**
     * base constructor - default content transfer encoding 7bit
     */
    public SMIMESignedGenerator()
    {
        _defaultContentTransferEncoding = "7bit";
    }

    /**
     * base constructor - default content transfer encoding explicitly set
     * 
     * @param defaultContentTransferEncoding new default to use.
     */
    public SMIMESignedGenerator(
        String defaultContentTransferEncoding)
    {
        _defaultContentTransferEncoding = defaultContentTransferEncoding;
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
        _signers.add(new Signer(key, cert, digestOID, null, null));
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
        _signers.add(new Signer(key, cert, digestOID, signedAttr, unsignedAttr));
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
        _certStores.add(certStore);
    }

    private void addHashHeader(
        StringBuffer header,
        List         signers)
    {
        int                 count = 0;
        
        //
        // build the hash header
        //
        Iterator   it = signers.iterator();
        Set        micAlgs = new HashSet();
        
        while (it.hasNext())
        {
            Signer       signer = (Signer)it.next();
            
            if (signer.getDigestOID().equals(DIGEST_SHA1))
            {
                micAlgs.add("sha1");
            }
            else if (signer.getDigestOID().equals(DIGEST_MD5))
            {
                micAlgs.add("md5");
            }
            else if (signer.getDigestOID().equals(DIGEST_SHA224))
            {
                micAlgs.add("sha224");
            }
            else if (signer.getDigestOID().equals(DIGEST_SHA256))
            {
                micAlgs.add("sha256");
            }
            else if (signer.getDigestOID().equals(DIGEST_SHA384))
            {
                micAlgs.add("sha384");
            }
            else if (signer.getDigestOID().equals(DIGEST_SHA512))
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
        try
        {
            MimeBodyPart sig = new MimeBodyPart();

            sig.setContent(new ContentSigner(content, false, sigProvider), DETACHED_SIGNATURE_TYPE);
            sig.addHeader("Content-Type", DETACHED_SIGNATURE_TYPE);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7s\"");
            sig.addHeader("Content-Description", "S/MIME Cryptographic Signature");
            sig.addHeader("Content-Transfer-Encoding", encoding);

            //
            // build the multipart header
            //
            StringBuffer        header = new StringBuffer(
                    "signed; protocol=\"application/pkcs7-signature\"");
                    
            addHashHeader(header, _signers);
            
            MimeMultipart   mm = new MimeMultipart(header.toString());

            mm.addBodyPart(content);
            mm.addBodyPart(sig);

            return mm;
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
        try
        {
            MimeBodyPart sig = new MimeBodyPart();
            
            sig.setContent(new ContentSigner(content, true, sigProvider), ENCAPSULATED_SIGNED_CONTENT_TYPE);
            sig.addHeader("Content-Type", ENCAPSULATED_SIGNED_CONTENT_TYPE);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7m\"");
            sig.addHeader("Content-Description", "S/MIME Cryptographic Signed Data");
            sig.addHeader("Content-Transfer-Encoding", encoding);
            
            return sig;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting body part together.", e);
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
        try
        {
            MimeBodyPart sig = new MimeBodyPart();
            
            sig.setContent(new ContentSigner(null, true, provider), CERTIFICATE_MANAGEMENT_CONTENT);
            sig.addHeader("Content-Type", CERTIFICATE_MANAGEMENT_CONTENT);
            sig.addHeader("Content-Disposition", "attachment; filename=\"smime.p7c\"");
            sig.addHeader("Content-Description", "S/MIME Certificate Management Message");
            sig.addHeader("Content-Transfer-Encoding", encoding);

            return sig;
        }
        catch (MessagingException e)
        {
            throw new SMIMEException("exception putting body part together.", e);
        }
    }
    
    private class Signer
    {
        final PrivateKey      key;
        final X509Certificate cert;
        final String          digestOID;
        final AttributeTable  signedAttr;
        final AttributeTable  unsignedAttr;
        
        Signer(
            PrivateKey      key,
            X509Certificate cert,
            String          digestOID,
            AttributeTable  signedAttr,
            AttributeTable  unsignedAttr)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.signedAttr = signedAttr;
            this.unsignedAttr = unsignedAttr;
        }

        public X509Certificate getCert()
        {
            return cert;
        }

        public String getDigestOID()
        {
            return digestOID;
        }

        public PrivateKey getKey()
        {
            return key;
        }

        public AttributeTable getSignedAttr()
        {
            return signedAttr;
        }

        public AttributeTable getUnsignedAttr()
        {
            return unsignedAttr;
        }
    }
    
    private class ContentSigner
        implements SMIMEStreamingProcessor
    {
        private final MimeBodyPart _content;
        private final boolean      _encapsulate;
        private final String       _provider;
        
        ContentSigner(
            MimeBodyPart content,
            boolean      encapsulate,
            String       provider)
        {
            _content = content;
            _encapsulate = encapsulate;
            _provider = provider;
        }
        
        protected CMSSignedDataStreamGenerator getGenerator()
            throws CMSException, CertStoreException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
        {
            CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();
            
            Iterator it = _certStores.iterator();
            
            while (it.hasNext())
            {
                gen.addCertificatesAndCRLs((CertStore)it.next());
            }
            
            it = _signers.iterator();
            
            while (it.hasNext())
            {
                Signer signer = (Signer)it.next();
                
                gen.addSigner(signer.getKey(), signer.getCert(), signer.getDigestOID(), signer.getSignedAttr(), signer.getUnsignedAttr(), _provider);
            }

            return gen;
        }
        
        public void write(OutputStream out)
            throws IOException
        {
            try
            {
                CMSSignedDataStreamGenerator gen = getGenerator();
                
                OutputStream signingStream = gen.open(out, _encapsulate);
                
                if (_content != null)
                {
                    if (!_encapsulate)
                    {
                        if (SMIMEUtil.isCanonicalisationRequired(_content, _defaultContentTransferEncoding))
                        {
                            signingStream = new CRLFOutputStream(signingStream);
                        }
                    }
    
                    _content.writeTo(signingStream);
                }
                
                signingStream.close();
            }
            catch (MessagingException e)
            {
                throw new IOException(e.toString());
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new IOException(e.toString());
            }
            catch (NoSuchProviderException e)
            {
                throw new IOException(e.toString());
            }
            catch (CMSException e)
            {
                throw new IOException(e.toString());
            }
            catch (InvalidKeyException e)
            {
                throw new IOException(e.toString());
            }
            catch (CertStoreException e)
            {
                throw new IOException(e.toString());
            }
        }
    }
}
