package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;

/**
 * general class for generating a pkcs7-signature message.
 * <p>
 * A simple example of usage.
 *
 * <pre>
 *      CertStore               certs...
 *      CMSSignedDataGenerator    gen = new CMSSignedDataGenerator();
 *
 *      gen.addSigner(privKey, cert, CMSSignedGenerator.DIGEST_SHA1);
 *      gen.addCertificatesAndCRLs(certs);
 *
 *      CMSSignedData           data = gen.generate(content, "BC");
 * </pre>
 */
public class CMSSignedDataGenerator
{
    CertStore                   certStore;
    List                        certs = new ArrayList();
    List                        crls = new ArrayList();
    List                        signerInfs = new ArrayList();
    List                        signers = new ArrayList();

    /**
     * Default type for the signed data.
     */
    public static final String  DATA = PKCSObjectIdentifiers.data.getId();
    
    public static final String  DIGEST_SHA1 = "1.3.14.3.2.26";
    public static final String  DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String  DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String  DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String  DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();
    public static final String  DIGEST_MD5 = "1.2.840.113549.2.5";
    public static final String  DIGEST_GOST3411 = CryptoProObjectIdentifiers.gostR3411.getId();

    public static final String  ENCRYPTION_RSA = "1.2.840.113549.1.1.1";
    public static final String  ENCRYPTION_DSA = "1.2.840.10040.4.3";
    public static final String  ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94.getId();
    public static final String  ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001.getId();
    
    static class DigOutputStream
        extends OutputStream
    {
        MessageDigest   dig;

        public DigOutputStream(
            MessageDigest   dig)
        {
            this.dig = dig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            dig.update(b, off, len);
        }

        public void write(
            int b)
            throws IOException
        {
            dig.update((byte)b);
        }
    }

    static class SigOutputStream
        extends OutputStream
    {
        Signature   sig;

        public SigOutputStream(
            Signature   sig)
        {
            this.sig = sig;
        }

        public void write(
            byte[]  b,
            int     off,
            int     len)
            throws IOException
        {
            try
            {
                sig.update(b, off, len);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }

        public void write(
            int b)
            throws IOException
        {
            try
            {
                sig.update((byte)b);
            }
            catch (SignatureException e)
            {
                throw new IOException("signature problem: " + e);
            }
        }
    }

    private class SignerInf
    {
        PrivateKey      key;
        X509Certificate cert;
        String          digestOID;
        String          encOID;
        AttributeTable  sAttr;
        AttributeTable  unsAttr;

        SignerInf(
            PrivateKey      key,
            X509Certificate cert,
            String          digestOID,
            String          encOID)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
        }

        SignerInf(
            PrivateKey      key,
            X509Certificate cert,
            String          digestOID,
            String          encOID,
            AttributeTable  sAttr,
            AttributeTable  unsAttr)
        {
            this.key = key;
            this.cert = cert;
            this.digestOID = digestOID;
            this.encOID = encOID;
            this.sAttr = sAttr;
            this.unsAttr = unsAttr;
        }

        PrivateKey getKey()
        {
            return key;
        }

        X509Certificate getCertificate()
        {
            return cert;
        }

        String getDigestAlgOID()
        {
            return digestOID;
        }

        byte[] getDigestAlgParams()
        {
            return null;
        }

        String getEncryptionAlgOID()
        {
            return encOID;
        }

        AttributeTable getSignedAttributes()
        {
            return sAttr;
        }

        AttributeTable getUnsignedAttributes()
        {
            return unsAttr;
        }
    
        /**
         * Return the digest algorithm using one of the standard JCA string
         * representations rather the the algorithm identifier (if possible).
         */
        String getDigestAlgName()
        {
            String  digestAlgOID = this.getDigestAlgOID();
            
            if (DIGEST_MD5.equals(digestAlgOID))
            {
                return "MD5";
            }
            else if (DIGEST_SHA1.equals(digestAlgOID))
            {
                return "SHA1";
            }
            else if (DIGEST_SHA224.equals(digestAlgOID))
            {
                return "SHA224";
            }
            else if (DIGEST_SHA256.equals(digestAlgOID))
            {
                return "SHA256";
            }
            else if (DIGEST_SHA384.equals(digestAlgOID))
            {
                return "SHA384";
            }
            else if (DIGEST_SHA512.equals(digestAlgOID))
            {
                return "SHA512";
            }
            else if (DIGEST_GOST3411.equals(digestAlgOID))
            {
                return "GOST3411";
            }
            else
            {
                return digestAlgOID;            
            }
        }
        
        /**
         * Return the digest encryption algorithm using one of the standard
         * JCA string representations rather the the algorithm identifier (if
         * possible).
         */
        String getEncryptionAlgName()
        {
            String  encryptionAlgOID = this.getEncryptionAlgOID();
            
            if (ENCRYPTION_DSA.equals(encryptionAlgOID))
            {
                return "DSA";
            }
            else if (ENCRYPTION_RSA.equals(encryptionAlgOID))
            {
                return "RSA";
            }
            else if (ENCRYPTION_GOST3410.equals(encryptionAlgOID))
            {
                return "GOST3410";
            }
            else if (ENCRYPTION_ECGOST3410.equals(encryptionAlgOID))
            {
                return "ECGOST3410";
            }
            else
            {
                return encryptionAlgOID;            
            }
        }    

        SignerInfo toSignerInfo(
            DERObjectIdentifier contentType,
            CMSProcessable      content,
            String              sigProvider,
            boolean             addDefaultAttributes)
            throws IOException, SignatureException, InvalidKeyException, NoSuchProviderException, NoSuchAlgorithmException, CertificateEncodingException, CMSException
        {
            AlgorithmIdentifier digAlgId = new AlgorithmIdentifier(
                  new DERObjectIdentifier(this.getDigestAlgOID()), new DERNull());
            AlgorithmIdentifier encAlgId;
            
            if (this.getEncryptionAlgOID().equals(ENCRYPTION_DSA))
            {
                encAlgId = new AlgorithmIdentifier(
                      new DERObjectIdentifier(this.getEncryptionAlgOID()));
            }
            else
            {
                encAlgId = new AlgorithmIdentifier(
                      new DERObjectIdentifier(this.getEncryptionAlgOID()), new DERNull());
            }

            ASN1Set         signedAttr = null;
            ASN1Set         unsignedAttr = null;
            Signature       sig = null;
            MessageDigest   dig = null;

            if(sigProvider != null)
            {
                sig = Signature.getInstance(this.getDigestAlgName() + "with" + this.getEncryptionAlgName(), sigProvider);
                try
                {
                    dig = MessageDigest.getInstance(this.getDigestAlgName(), sigProvider);
                }
                catch (NoSuchAlgorithmException e)
                {
                    dig = MessageDigest.getInstance(this.getDigestAlgName());
                }
            }
            else
            {
                sig = Signature.getInstance(this.getDigestAlgName() + "with" + this.getEncryptionAlgName());
                dig = MessageDigest.getInstance(this.getDigestAlgName());
            }                

            byte[]      hash = null;

            if (content != null)
            {
                content.write(new DigOutputStream(dig));

                hash = dig.digest();
            }

            AttributeTable   attr = this.getSignedAttributes();

            if (attr != null)
            {
                ASN1EncodableVector  v = new ASN1EncodableVector();

                if (attr.get(CMSAttributes.contentType) == null)
                {
                    v.add(new Attribute(CMSAttributes.contentType,
                                                   new DERSet(contentType)));
                }
                else
                {
                    v.add(attr.get(CMSAttributes.contentType));
                }

                if (attr.get(CMSAttributes.signingTime) == null)
                {
                    v.add(new Attribute(CMSAttributes.signingTime,
                                           new DERSet(new Time(new Date()))));
                }
                else
                {
                    v.add(attr.get(CMSAttributes.signingTime));
                }

                if (hash != null)
                {
                    v.add(new Attribute(CMSAttributes.messageDigest,
                        new DERSet(new DEROctetString(hash))));
                }
                else
                {
                    v.add(new Attribute(CMSAttributes.messageDigest,
                        new DERSet(new DERNull())));
                }
                
                Hashtable           ats = attr.toHashtable();
                
                ats.remove(CMSAttributes.contentType);
                ats.remove(CMSAttributes.signingTime);
                ats.remove(CMSAttributes.messageDigest);
                
                Iterator            it = ats.values().iterator();
                
                while (it.hasNext())
                {
                    v.add(Attribute.getInstance(it.next()));
                }
                
                signedAttr = new DERSet(v);
            }
            else
            {
                if (addDefaultAttributes) 
                {
                    ASN1EncodableVector  v = new ASN1EncodableVector();

                    v.add(new Attribute(
                        CMSAttributes.contentType,
                            new DERSet(contentType)));

                    v.add(new Attribute(
                        CMSAttributes.signingTime,
                            new DERSet(new DERUTCTime(new Date()))));

                    if (hash != null)
                    {
                        v.add(new Attribute(CMSAttributes.messageDigest,
                            new DERSet(new DEROctetString(hash))));
                    }
                    else
                    {
                        v.add(new Attribute(CMSAttributes.messageDigest,
                            new DERSet(new DERNull())));
                    }

                    signedAttr = new DERSet(v);
                }
            }

            attr = this.getUnsignedAttributes();

            if (attr != null)
            {
                Hashtable           ats = attr.toHashtable();
                Iterator            it = ats.values().iterator();
                ASN1EncodableVector  v = new ASN1EncodableVector();

                while (it.hasNext())
                {
                    v.add(Attribute.getInstance(it.next()));
                }

                unsignedAttr = new DERSet(v);
            }

            //
            // sig must be composed from the DER encoding.
            //
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
 
            if (signedAttr != null) 
            {
                DEROutputStream         dOut = new DEROutputStream(bOut);
                dOut.writeObject(signedAttr);
            } 
            else
            {
                content.write(bOut);
            }
            sig.initSign(key);

            sig.update(bOut.toByteArray());

            ASN1OctetString         encDigest = new DEROctetString(sig.sign());
            X509Certificate         cert = this.getCertificate();
            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getTBSCertificate());
            ASN1InputStream         aIn = new ASN1InputStream(bIn);
            TBSCertificateStructure tbs = TBSCertificateStructure.getInstance(aIn.readObject());
            IssuerAndSerialNumber   encSid = new IssuerAndSerialNumber(tbs.getIssuer(), tbs.getSerialNumber().getValue());

            return new SignerInfo(new SignerIdentifier(encSid), digAlgId,
                        signedAttr, encAlgId, encDigest, unsignedAttr);
        }

    }

    /**
     * base constructor
     */
    public CMSSignedDataGenerator()
    {
    }

    private String getEncOID(
        PrivateKey key,
        String     digestOID)
    {
        String encOID = null;
        
        if (key instanceof RSAPrivateKey || "RSA".equalsIgnoreCase(key.getAlgorithm()))
        {
            encOID = ENCRYPTION_RSA;
        }
        else if (key instanceof DSAPrivateKey || "DSA".equalsIgnoreCase(key.getAlgorithm()))
        {
            encOID = ENCRYPTION_DSA;
            if (!digestOID.equals(DIGEST_SHA1))
            {
                throw new IllegalArgumentException("can't mix DSA with anything but SHA1");
            }
        }
        else if (key instanceof GOST3410PrivateKey || "GOST3410".equalsIgnoreCase(key.getAlgorithm()))
        {
            encOID = ENCRYPTION_GOST3410;
        }
        else if ("ECGOST3410".equalsIgnoreCase(key.getAlgorithm()))
        {
            encOID = ENCRYPTION_ECGOST3410;
        }
        
        return encOID;
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
        String  encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID));
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
        String  encOID = getEncOID(key, digestOID);

        signerInfs.add(new SignerInf(key, cert, digestOID, encOID, signedAttr, unsignedAttr));
    }

    /**
     * Add a store of precalculated signers to the generator.
     * 
     * @param signerStore
     */
    public void addSigners(
        SignerInformationStore    signerStore)
    {
        Iterator    it = signerStore.getSigners().iterator();
        
        while (it.hasNext())
        {
            signers.add(it.next());
        }
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
        throws CertStoreException, CMSException
    {
        //
        // divide up the certs and crls.
        //
        try
        {
            Iterator  it = certStore.getCertificates(null).iterator();

            while (it.hasNext())
            {
                X509Certificate         c = (X509Certificate)it.next();

                certs.add(new X509CertificateStructure(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error processing certs", e);
        }
        catch (CertificateEncodingException e)
        {
            throw new CMSException("error encoding certs", e);
        }

        try
        {
            Iterator    it = certStore.getCRLs(null).iterator();

            while (it.hasNext())
            {
                X509CRL                 c = (X509CRL)it.next();

                crls.add(new CertificateList(
                                        (ASN1Sequence)makeObj(c.getEncoded())));
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error processing crls", e);
        }
        catch (CRLException e)
        {
            throw new CMSException("error encoding crls", e);
        }
    }

    private DERObject makeObj(
        byte[]  encoding)
        throws IOException
    {
        if (encoding == null)
        {
            return null;
        }

        ByteArrayInputStream    bIn = new ByteArrayInputStream(encoding);
        ASN1InputStream         aIn = new ASN1InputStream(bIn);

        return aIn.readObject();
    }

    private AlgorithmIdentifier makeAlgId(
        String  oid,
        byte[]  params)
        throws IOException
    {
        if (params != null)
        {
            return new AlgorithmIdentifier(
                            new DERObjectIdentifier(oid), makeObj(params));
        }
        else
        {
            return new AlgorithmIdentifier(
                            new DERObjectIdentifier(oid), new DERNull());
        }
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider.
     */
    public CMSSignedData generate(
        CMSProcessable content,
        String         sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(content, false, sigProvider);
    }

    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature. The content type
     * is set according to the OID represented by the string signedContentType.
     */
    public CMSSignedData generate(
        String          signedContentType,
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return generate(signedContentType, content, encapsulate, sigProvider, true);
    }
    
    /**
     * Similar method to the other generate methods. The additional argument
     * addDefaultAttributes indicates whether or not a default set of signed attributes
     * need to be added automatically. If the argument is set to false, no
     * attributes will get added at all. 
     */
    public CMSSignedData generate(
        String                    signedContentType,
        CMSProcessable          content,
        boolean                     encapsulate,
        String                  sigProvider,
        boolean                    addDefaultAttributes)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        ASN1EncodableVector  digestAlgs = new ASN1EncodableVector();
        ASN1EncodableVector  signerInfos = new ASN1EncodableVector();

        DERObjectIdentifier      contentTypeOID = new DERObjectIdentifier(signedContentType);
        
        //
        // add the precalculated SignerInfo objects.
        //
        Iterator            it = signers.iterator();
        
        while (it.hasNext())
        {
            SignerInformation        signer = (SignerInformation)it.next();
            AlgorithmIdentifier     digAlgId;
            
            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(),
                                                       signer.getDigestAlgParams());
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }

           digestAlgs.add(digAlgId);

           signerInfos.add(signer.toSignerInfo());
        }
        
        //
        // add the SignerInfo objects
        //
        it = signerInfs.iterator();

        while (it.hasNext())
        {
            SignerInf                   signer = (SignerInf)it.next();
            AlgorithmIdentifier     digAlgId;

            try
            {
                digAlgId = makeAlgId(signer.getDigestAlgOID(),
                                            signer.getDigestAlgParams());

                digestAlgs.add(digAlgId);

                signerInfos.add(signer.toSignerInfo(contentTypeOID, content, sigProvider, addDefaultAttributes));
            }
            catch (IOException e)
            {
                throw new CMSException("encoding error.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CMSException("key inappropriate for signature.", e);
            }
            catch (SignatureException e)
            {
                throw new CMSException("error creating signature.", e);
            }
            catch (CertificateEncodingException e)
            {
                throw new CMSException("error creating sid.", e);
            }
        }

        ASN1Set certificates = null;

        if (certs.size() != 0)
        {
            ASN1EncodableVector  v = new ASN1EncodableVector();

            it = certs.iterator();
            while (it.hasNext())
            {
                v.add((DEREncodable)it.next());
            }

            certificates = new DERSet(v);
        }

        ASN1Set certrevlist = null;

        if (crls.size() != 0)
        {
            ASN1EncodableVector  v = new ASN1EncodableVector();

            it = crls.iterator();
            while (it.hasNext())
            {
                v.add((DEREncodable)it.next());
            }

            certrevlist = new DERSet(v);
        }

        ContentInfo    encInfo;
        
        if (encapsulate)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();

            try
            {
                content.write(bOut);
            }
            catch (IOException e)
            {
                throw new CMSException("encapsulation error.", e);
            }

            ASN1OctetString  octs = new BERConstructedOctetString(
                                                    bOut.toByteArray());

            encInfo = new ContentInfo(contentTypeOID, octs);
        }
        else
        {
            encInfo = new ContentInfo(contentTypeOID, null);
        }

        SignedData  sd = new SignedData(
                                 new DERSet(digestAlgs),
                                 encInfo, 
                                 certificates, 
                                 certrevlist, 
                                 new DERSet(signerInfos));

        ContentInfo contentInfo = new ContentInfo(
                PKCSObjectIdentifiers.signedData, sd);

        return new CMSSignedData(content, contentInfo);
    }
    
    /**
     * generate a signed object that for a CMS Signed Data
     * object using the given provider - if encapsulate is true a copy
     * of the message will be included in the signature with the
     * default content type "data".
     */
    public CMSSignedData generate(
        CMSProcessable  content,
        boolean         encapsulate,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return this.generate(DATA, content, encapsulate, sigProvider);
    }
}
