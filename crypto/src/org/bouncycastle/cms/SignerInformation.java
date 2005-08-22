package org.bouncycastle.cms;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Iterator;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;

/**
 * an expanded SignerInfo block from a CMS Signed message
 */
public class SignerInformation
{
    private SignerId                sid;
    private SignerInfo              info;
    private AlgorithmIdentifier     digestAlgorithm;
    private AlgorithmIdentifier     encryptionAlgorithm;
    private ASN1Set                 signedAttributes;
    private ASN1Set                 unsignedAttributes;
    private CMSProcessable          content;
    private byte[]                  signature;
    private DERObjectIdentifier     contentType;
    private byte[]                  _digest;

    SignerInformation(
        SignerInfo          info,
        DERObjectIdentifier contentType,
        CMSProcessable      content,
        byte[]              digest)
    {
        this.info = info;
        this.sid = new SignerId();
        this.contentType = contentType;


        try
        {
            SignerIdentifier   s = info.getSID();

            if (s.isTagged())
            {
                ASN1OctetString octs = ASN1OctetString.getInstance(s.getId());

                sid.setSubjectKeyIdentifier(octs.getOctets());
            }
            else
            {
                IssuerAndSerialNumber   iAnds = IssuerAndSerialNumber.getInstance(s.getId());

                ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
                ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

                aOut.writeObject(iAnds.getName());

                sid.setIssuer(bOut.toByteArray());
                sid.setSerialNumber(iAnds.getSerialNumber().getValue());
            }
        }
        catch (IOException e)
        {
            throw new IllegalArgumentException("invalid sid in SignerInfo");
        }

        this.digestAlgorithm = info.getDigestAlgorithm();
        this.signedAttributes = info.getAuthenticatedAttributes();
        this.unsignedAttributes = info.getUnauthenticatedAttributes();
        this.encryptionAlgorithm = info.getDigestEncryptionAlgorithm();
        this.signature = info.getEncryptedDigest().getOctets();

        this.content = content;
        _digest = digest;
    }

    private byte[] encodeObj(
        DEREncodable    obj)
        throws IOException
    {
        if (obj != null)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(obj);

            return bOut.toByteArray();
        }

        return null;
    }

    public SignerId getSID()
    {
        return sid;
    }

    /**
     * return the object identifier for the signature.
     */
    public String getDigestAlgOID()
    {
        return digestAlgorithm.getObjectId().getId();
    }

    /**
     * return the signature parameters, or null if there aren't any.
     */
    public byte[] getDigestAlgParams()
    {
        try
        {
            return encodeObj(digestAlgorithm.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting digest parameters " + e);
        }
    }

    /**
     * return the object identifier for the signature.
     */
    public String getEncryptionAlgOID()
    {
        return encryptionAlgorithm.getObjectId().getId();
    }

    /**
     * return the signature/encyrption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams()
    {
        try
        {
            return encodeObj(encryptionAlgorithm.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }
    
    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    String getDigestAlgName()
    {
        String  digestAlgOID = this.getDigestAlgOID();
        
        if (CMSSignedDataGenerator.DIGEST_MD5.equals(digestAlgOID))
        {
            return "MD5";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA1.equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA224.equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA256.equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA384.equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (CMSSignedDataGenerator.DIGEST_SHA512.equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (PKCSObjectIdentifiers.sha1WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA1";
        }
        else if (PKCSObjectIdentifiers.sha224WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA224";
        }
        else if (PKCSObjectIdentifiers.sha256WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA256";
        }
        else if (PKCSObjectIdentifiers.sha384WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA384";
        }
        else if (PKCSObjectIdentifiers.sha512WithRSAEncryption.getId().equals(digestAlgOID))
        {
            return "SHA512";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd128.getId().equals(digestAlgOID))
        {
            return "RIPEMD128";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd160.getId().equals(digestAlgOID))
        {
            return "RIPEMD160";
        }
        else if (TeleTrusTObjectIdentifiers.ripemd256.getId().equals(digestAlgOID))
        {
            return "RIPEMD256";
        }
        else if (CryptoProObjectIdentifiers.gostR3411.getId().equals(digestAlgOID))
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
        
        if (CMSSignedDataGenerator.ENCRYPTION_DSA.equals(encryptionAlgOID))
        {
            return "DSA";
        }
        else if ("1.2.840.10040.4.1".equals(encryptionAlgOID))
        {
            return "DSA";
        }
        else if (CMSSignedDataGenerator.ENCRYPTION_RSA.equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if (CMSSignedDataGenerator.ENCRYPTION_GOST3410.equals(encryptionAlgOID))
        {
            return "GOST3410";
        }
        else if (CMSSignedDataGenerator.ENCRYPTION_ECGOST3410.equals(encryptionAlgOID))
        {
            return "ECGOST3410";
        }
        else if ("1.2.840.113549.1.1.5".equals(encryptionAlgOID))
        {
            return "RSA";
        }
        else if (encryptionAlgOID.startsWith(TeleTrusTObjectIdentifiers.teleTrusTRSAsignatureAlgorithm))
        {
            return "RSA";
        }
        else
        {
            return encryptionAlgOID;            
        }
    }    

    /**
     * return a table of the signed attributes - indexed by
     * the OID of the attribute.
     */
    public AttributeTable getSignedAttributes()
    {
        if (signedAttributes == null)
        {
            return null;
        }

        return new AttributeTable(signedAttributes);
    }

    /**
     * return a table of the unsigned attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnsignedAttributes()
    {
        if (unsignedAttributes == null)
        {
            return null;
        }

        return new AttributeTable(unsignedAttributes);
    }

    /**
     * return the encoded signature
     */
    public byte[] getSignature()
    {
        return signature;
    }

    private boolean doVerify(
        PublicKey       key,
        AttributeTable  signedAttrTable,
        String          sigProvider)
        throws CMSException, NoSuchAlgorithmException, NoSuchProviderException
    {
        Signature       sig;
        MessageDigest   digest;
        
        if (sigProvider != null)
        {
            sig = Signature.getInstance(this.getDigestAlgName() + "with" + this.getEncryptionAlgName(), sigProvider);
            try
            {
                digest = MessageDigest.getInstance(this.getDigestAlgName(), sigProvider);
            }
            catch (NoSuchAlgorithmException e)
            {
                digest = MessageDigest.getInstance(this.getDigestAlgName());
            }
        }
        else
        {
            sig = Signature.getInstance(this.getDigestAlgName() + "with" + this.getEncryptionAlgName());
            digest = MessageDigest.getInstance(this.getDigestAlgName());
        }
        
        try
        {
            sig.initVerify(key);
            
            if (content == null && _digest == null)
            {
                throw new IllegalArgumentException("no content specified for signature verification.");
            }

            if (signedAttributes == null)
            {
                content.write(
                        new CMSSignedDataGenerator.SigOutputStream(sig));
            }
            else
            {
                byte[]  hash;
                
                if (content != null)
                {
                    content.write(
                            new CMSSignedDataGenerator.DigOutputStream(digest));
    
                    hash = digest.digest();
                }
                else
                {
                    hash = _digest;
                }

                Attribute dig = signedAttrTable.get(
                                CMSAttributes.messageDigest);
                Attribute type = signedAttrTable.get(
                                CMSAttributes.contentType);

                if (dig == null)
                {
                    throw new SignatureException("no hash for content found in signed attributes");
                }

                if (type == null)
                {
                    throw new SignatureException("no content type id found in signed attributes");
                }

                byte[]  signedHash = ((ASN1OctetString)dig.getAttrValues().getObjectAt(0)).getOctets();

                if (!MessageDigest.isEqual(hash, signedHash))
                {
                    throw new SignatureException("content hash found in signed attributes different");
                }

                DERObjectIdentifier  typeOID = (DERObjectIdentifier)type.getAttrValues().getObjectAt(0);

                if (!typeOID.equals(contentType))
                {
                    throw new SignatureException("contentType in signed attributes different");
                }

                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                DEROutputStream dOut = new DEROutputStream(bOut);

                dOut.writeObject(signedAttributes);

                dOut.close();

                sig.update(bOut.toByteArray());
            }

            return sig.verify(this.getSignature());
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException(
                    "key not appropriate to signature in message.", e);
        }
        catch (IOException e)
        {
            throw new CMSException(
                    "can't process mime object to create signature.", e);
        }
        catch (SignatureException e)
        {
            throw new CMSException(
                    "invalid signature format in message: + " + e.getMessage(), e);
        }
    }

    /**
     * verify that the given public key succesfully handles and confirms the
     * signature associated with this signer.
     */
    public boolean verify(
        PublicKey   key,
        String      sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        return doVerify(key, this.getSignedAttributes(), sigProvider); 
    }

    /**
     * verify that the given certificate succesfully handles and confirms
     * the signature associated with this signer and, if a signingTime
     * attribute is available, that the certificate was valid at the time the
     * signature was generated.
     */
    public boolean verify(
        X509Certificate cert,
        String          sigProvider)
        throws NoSuchAlgorithmException, NoSuchProviderException,
            CertificateExpiredException, CertificateNotYetValidException,
            CMSException
    {
        AttributeTable attr = this.getSignedAttributes();

        if (attr != null)
        {
            Attribute t = attr.get(CMSAttributes.signingTime);

            if (t != null)
            {
                Time   time = Time.getInstance(
                                    t.getAttrValues().getObjectAt(0).getDERObject());

                cert.checkValidity(time.getDate());
            }
        }

        return doVerify(cert.getPublicKey(), attr, sigProvider); 
    }
    
    SignerInfo toSignerInfo()
    {
        return info;
    }
    
    /**
     * Return a signer information object with the passed in unsigned
     * attributes replacing the ones that are current associated with
     * the object passed in.
     * 
     * @param signerInformation the signerInfo to be used as the basis.
     * @param unsignedAttributes the unsigned attributes to add.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    public static SignerInformation replaceUnsignedAttributes(
        SignerInformation   signerInformation,
        AttributeTable      unsignedAttributes)
    {
        SignerInfo  sInfo = signerInformation.info;
        ASN1Set     unsignedAttr = null;
        
        if (unsignedAttributes != null)
        {
            Hashtable           ats = unsignedAttributes.toHashtable();
            Iterator            it = ats.values().iterator();
            ASN1EncodableVector  v = new ASN1EncodableVector();

            while (it.hasNext())
            {
                v.add(Attribute.getInstance(it.next()));
            }

            unsignedAttr = new DERSet(v);
        }
        
        return new SignerInformation(
                new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
                    sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), unsignedAttr),
                    signerInformation.contentType, signerInformation.content, null);
    }
}
