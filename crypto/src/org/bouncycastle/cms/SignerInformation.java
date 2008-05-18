package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.SignerIdentifier;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;

import javax.crypto.Cipher;

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
    private DigestCalculator        digestCalculator;
    private byte[]                  resultDigest;

    SignerInformation(
        SignerInfo          info,
        DERObjectIdentifier contentType,
        CMSProcessable      content,
        DigestCalculator digestCalculator)
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

                sid.setIssuer(iAnds.getName().getEncoded());
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
        this.digestCalculator = digestCalculator;
    }

    private byte[] encodeObj(
        DEREncodable    obj)
        throws IOException
    {
        if (obj != null)
        {
            return obj.getDERObject().getEncoded();
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
     * return the content digest that was calculated during verification.
     */
    public byte[] getContentDigest()
    {
        if (resultDigest == null)
        {
            throw new IllegalStateException("method can only be called after verify.");
        }
        
        return (byte[])resultDigest.clone();
    }
    
    /**
     * return the object identifier for the signature.
     */
    public String getEncryptionAlgOID()
    {
        return encryptionAlgorithm.getObjectId().getId();
    }

    /**
     * return the signature/encryption algorithm parameters, or null if
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
        return (byte[])signature.clone();
    }

    /**
     * Return a SignerInformationStore containing the counter signatures attached to this
     * signer. If no counter signatures are present an empty store is returned.
     */
    public SignerInformationStore getCounterSignatures()
    {
        AttributeTable unsignedAttributeTable = getUnsignedAttributes();
        if (unsignedAttributeTable == null)
        {
            return new SignerInformationStore(new ArrayList(0));
        }
        
        List counterSignatures = new ArrayList();

        Attribute counterSignatureAttribute = unsignedAttributeTable.get(CMSAttributes.counterSignature);
        if (counterSignatureAttribute != null)
        {
            ASN1Set values = counterSignatureAttribute.getAttrValues();
            counterSignatures = new ArrayList(values.size());

            for (Enumeration en = values.getObjects(); en.hasMoreElements();)
            {
                SignerInfo si = SignerInfo.getInstance(en.nextElement());

                String          digestName = CMSSignedHelper.INSTANCE.getDigestAlgName(si.getDigestAlgorithm().getObjectId().getId());
                
                counterSignatures.add(new SignerInformation(si, CMSAttributes.counterSignature, null, new CounterSignatureDigestCalculator(digestName, null, getSignature())));
            }
        }

        return new SignerInformationStore(counterSignatures);
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
            return signedAttributes.getEncoded(ASN1Encodable.DER);
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

        // TODO [BJA-109] Note: PSSParameterSpec requires JDK1.4+ 
/*
        try
        {
            DERObjectIdentifier sigAlgOID = encryptionAlgorithm.getObjectId();
            if (sigAlgOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS))
            {
                DERObject sigParams = this.encryptionAlgorithm.getParameters()
                    .getDERObject();

                // RFC 4056
                // When the id-RSASSA-PSS algorithm identifier is used for a signature,
                // the AlgorithmIdentifier parameters field MUST contain RSASSA-PSS-params.
                if (sigParams == null || sigParams instanceof ASN1Null)
                {
                    throw new CMSException(
                        "RSASSA-PSS signature must specify algorithm parameters");
                }

                AlgorithmParameters params = AlgorithmParameters.getInstance(
                    sigAlgOID.getId(), sig.getProvider().getName());
                params.init(sigParams.getEncoded(), "ASN.1");

                PSSParameterSpec spec = (PSSParameterSpec)params.getParameterSpec(PSSParameterSpec.class);
                sig.setParameter(spec);
            }
            else
            {
                // TODO Are there other signature algorithms that provide parameters?
                if (sigParams != null && !(sigParams instanceof ASN1Null))
                {
                    throw new CMSException("unrecognised signature parameters provided");
                }
            }
        }
        catch (IOException e)
        {
            throw new CMSException("error encoding signature parameters.", e);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new CMSException("error setting signature parameters.", e);
        }
        catch (InvalidParameterSpecException e)
        {
            throw new CMSException("error processing signature parameters.", e);
        }
*/

        try
        {
            sig.initVerify(key);
            
            if (signedAttributes == null)
            {
                if (content != null)
                {
                    content.write(
                            new CMSSignedDataGenerator.SigOutputStream(sig));
                    content.write(
                            new CMSSignedDataGenerator.DigOutputStream(digest));
    
                    resultDigest = digest.digest();
                }
                else
                {
                    resultDigest = digestCalculator.getDigest();
                    
                    // need to decrypt signature and check message bytes
                    return verifyDigest(resultDigest, key, this.getSignature(), sigProvider);
                }
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
                else if (digestCalculator != null)
                {
                    hash = digestCalculator.getDigest();
                }
                else
                {
                    hash = null;
                }

                resultDigest = hash;
                
                Attribute dig = signedAttrTable.get(
                                CMSAttributes.messageDigest);
                Attribute type = signedAttrTable.get(
                                CMSAttributes.contentType);

                if (dig == null)
                {
                    throw new SignatureException("no hash for content found in signed attributes");
                }

                if (type == null && !contentType.equals(CMSAttributes.counterSignature))
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

                if (type != null)
                {
                    DERObjectIdentifier  typeOID = (DERObjectIdentifier)type.getAttrValues().getObjectAt(0);

                    if (!typeOID.equals(contentType))
                    {
                        throw new SignatureException("contentType in signed attributes different");
                    }
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
                    "invalid signature format in message: " + e.getMessage(), e);
        }
    }

    private boolean isNull(
        DEREncodable    o)
    {
        return (o instanceof ASN1Null) || (o == null);
    }
    
    private DigestInfo derDecode(
        byte[]  encoding)
        throws IOException, CMSException
    {
        if (encoding[0] != (DERTags.CONSTRUCTED | DERTags.SEQUENCE))
        {
            throw new IOException("not a digest info object");
        }
        
        ASN1InputStream         aIn = new ASN1InputStream(encoding);

        DigestInfo digInfo = new DigestInfo((ASN1Sequence)aIn.readObject());

        // length check to avoid Bleichenbacher vulnerability

        if (digInfo.getEncoded().length != encoding.length)
        {
            throw new CMSException("malformed RSA signature");
        }

        return digInfo;
    }
    
    private boolean verifyDigest(
        byte[]    digest, 
        PublicKey key,
        byte[]    signature,
        String    sigProvider) 
        throws NoSuchAlgorithmException, NoSuchProviderException, CMSException
    {
        String algorithm = CMSSignedHelper.INSTANCE.getEncryptionAlgName(this.getEncryptionAlgOID());
        
        try
        {
            if (algorithm.equals("RSA"))
            {
                Cipher c;
                if (sigProvider != null)
                {
                    c = Cipher.getInstance("RSA/ECB/PKCS1Padding", sigProvider);
                }
                else
                {
                    c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                }
                
                c.init(Cipher.DECRYPT_MODE, key);
                
                DigestInfo digInfo = derDecode(c.doFinal(signature));

                if (!digInfo.getAlgorithmId().getObjectId().equals(digestAlgorithm.getObjectId()))
                {
                    return false;
                }
             
                if (!isNull(digInfo.getAlgorithmId().getParameters()))
                {
                    return false;
                }

                byte[]  sigHash = digInfo.getDigest();

                return MessageDigest.isEqual(digest, sigHash);
            }
            else if (algorithm.equals("DSA"))
            {
                Signature sig;
                if (sigProvider != null)
                {
                    sig = Signature.getInstance("NONEwithDSA", sigProvider);
                }
                else
                {
                    sig = Signature.getInstance("NONEwithDSA");
                }
                
                sig.initVerify(key);
                
                sig.update(digest);
                
                return sig.verify(signature);
            }
            else
            {
                throw new CMSException("algorithm: " + algorithm + " not supported in base signatures.");
            }
        }
        catch (GeneralSecurityException e)
        {
            throw new CMSException("Exception processing signature: " + e, e);
        }
        catch (IOException e)
        {
            throw new CMSException("Exception decoding signature: " + e, e);
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
     * verify that the given certificate successfully handles and confirms
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
            ASN1EncodableVector v = attr.getAll(CMSAttributes.signingTime);
            switch (v.size())
            {
                case 0:
                    break;
                case 1:
                {
                    Attribute t = (Attribute)v.get(0);
//                    assert t != null;

                    ASN1Set attrValues = t.getAttrValues();
                    if (attrValues.size() != 1)
                    {
                        throw new CMSException("A signing-time attribute MUST have a single attribute value");
                    }

                    Time time = Time.getInstance(attrValues.getObjectAt(0).getDERObject());

                    cert.checkValidity(time.getDate());
                    break;
                }
                default:
                    throw new CMSException("The SignedAttributes in a signerInfo MUST NOT include multiple instances of the signing-time attribute");
            }
        }

        return doVerify(cert.getPublicKey(), attr, sigProvider); 
    }
    
    /**
     * Return the base ASN.1 CMS structure that this object contains.
     * 
     * @return an object containing a CMS SignerInfo structure.
     */
    public SignerInfo toSignerInfo()
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

    /**
     * Return a signer information object with passed in SignerInformationStore representing counter
     * signatures attached as an unsigned attribute.
     *
     * @param signerInformation the signerInfo to be used as the basis.
     * @param counterSigners signer info objects carrying counter signature.
     * @return a copy of the original SignerInformationObject with the changed attributes.
     */
    public static SignerInformation addCounterSigners(
        SignerInformation        signerInformation,
        SignerInformationStore   counterSigners)
    {
        SignerInfo          sInfo = signerInformation.info;
        AttributeTable      unsignedAttr = signerInformation.getUnsignedAttributes();
        ASN1EncodableVector v;

        if (unsignedAttr != null)
        {
            v = unsignedAttr.toASN1EncodableVector();
        }
        else
        {
            v = new ASN1EncodableVector();
        }

        ASN1EncodableVector sigs = new ASN1EncodableVector();

        for (Iterator it = counterSigners.getSigners().iterator(); it.hasNext();)
        {
            sigs.add(((SignerInformation)it.next()).toSignerInfo());
        }

        v.add(new Attribute(CMSAttributes.counterSignature, new DERSet(sigs)));

        return new SignerInformation(
                new SignerInfo(sInfo.getSID(), sInfo.getDigestAlgorithm(),
                    sInfo.getAuthenticatedAttributes(), sInfo.getDigestEncryptionAlgorithm(), sInfo.getEncryptedDigest(), new DERSet(v)),
                    signerInformation.contentType, signerInformation.content, null);
    }
}