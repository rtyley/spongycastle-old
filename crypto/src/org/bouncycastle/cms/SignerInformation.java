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

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

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
     * return the version number for this objects underlying SignerInfo structure.
     */
    public int getVersion()
    {
        return info.getVersion().getValue().intValue();
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

    /**
     * return the DER encoding of the signed attributes.
     * @throws IOException if an encoding error occurs.
     */
    public byte[] getEncodedSignedAttributes()
        throws IOException
    {
        if (signedAttributes != null)
        {
            ByteArrayOutputStream  bOut = new ByteArrayOutputStream();
            DEROutputStream        aOut = new DEROutputStream(bOut);

            aOut.writeObject(signedAttributes);

            return bOut.toByteArray();
        }

        return null;
    }
    
    private boolean doVerify(
        PublicKey       key,
        AttributeTable  signedAttrTable,
        String          sigProvider)
        throws CMSException, NoSuchAlgorithmException, NoSuchProviderException
    {
        String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(this.getDigestAlgOID());
        String          signatureName = digestName + "with" + CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
        Signature       sig = CMSSignedHelper.INSTANCE.getSignatureInstance(signatureName, sigProvider);
        MessageDigest   digest = CMSSignedHelper.INSTANCE.getDigestInstance(digestName, sigProvider); 
        
        try
        {
            sig.initVerify(key);
            
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

                DERObject hashObj = dig.getAttrValues().getObjectAt(0).getDERObject();
                
                if (hashObj instanceof ASN1OctetString)
                {
                    byte[]  signedHash = ((ASN1OctetString)hashObj).getOctets();
    
                    if (!MessageDigest.isEqual(hash, signedHash))
                    {
                        throw new SignatureException("content hash found in signed attributes different");
                    }
                }
                else if (hashObj instanceof DERNull)
                {
                    if (hash != null)
                    {
                        throw new SignatureException("NULL hash found in signed attributes when one expected");
                    }
                }

                DERObjectIdentifier  typeOID = (DERObjectIdentifier)type.getAttrValues().getObjectAt(0);

                if (!typeOID.equals(contentType))
                {
                    throw new SignatureException("contentType in signed attributes different");
                }

                sig.update(this.getEncodedSignedAttributes());
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
    
    /**
     * Return the base ASN.1 CMS structure that this object contains.
     * 
     * @return an object containing a CMS SignerInfo structure.
     */
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
            unsignedAttr = new DERSet(unsignedAttributes.toASN1EncodableVector());
        }
        
        return new SignerInformation(
                new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
                    sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), unsignedAttr),
                    signerInformation.contentType, signerInformation.content, null);
    }
}

