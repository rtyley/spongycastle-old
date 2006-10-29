package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.interfaces.GOST3410PrivateKey;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class CMSSignedGenerator
{
    /**
     * Default type for the signed data.
     */
    public static final String  DATA = PKCSObjectIdentifiers.data.getId();
    
    public static final String  DIGEST_SHA1 = OIWObjectIdentifiers.idSHA1.getId();
    public static final String  DIGEST_SHA224 = NISTObjectIdentifiers.id_sha224.getId();
    public static final String  DIGEST_SHA256 = NISTObjectIdentifiers.id_sha256.getId();
    public static final String  DIGEST_SHA384 = NISTObjectIdentifiers.id_sha384.getId();
    public static final String  DIGEST_SHA512 = NISTObjectIdentifiers.id_sha512.getId();
    public static final String  DIGEST_MD5 = PKCSObjectIdentifiers.md5.getId();
    public static final String  DIGEST_GOST3411 = CryptoProObjectIdentifiers.gostR3411.getId();
    public static final String  DIGEST_RIPEMD128 = TeleTrusTObjectIdentifiers.ripemd128.getId();
    public static final String  DIGEST_RIPEMD160 = TeleTrusTObjectIdentifiers.ripemd160.getId();
    public static final String  DIGEST_RIPEMD256 = TeleTrusTObjectIdentifiers.ripemd256.getId();

    public static final String  ENCRYPTION_RSA = PKCSObjectIdentifiers.rsaEncryption.getId();
    public static final String  ENCRYPTION_DSA = X9ObjectIdentifiers.id_dsa_with_sha1.getId();
    public static final String  ENCRYPTION_ECDSA = X9ObjectIdentifiers.ecdsa_with_SHA1.getId();
    public static final String  ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers.id_RSASSA_PSS.getId();
    public static final String  ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers.gostR3410_94.getId();
    public static final String  ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers.gostR3410_2001.getId();

    private static final String  ENCRYPTION_ECDSA_WITH_SHA1 = X9ObjectIdentifiers.ecdsa_with_SHA1.getId();
    private static final String  ENCRYPTION_ECDSA_WITH_SHA224 = X9ObjectIdentifiers.ecdsa_with_SHA224.getId();
    private static final String  ENCRYPTION_ECDSA_WITH_SHA256 = X9ObjectIdentifiers.ecdsa_with_SHA256.getId();
    private static final String  ENCRYPTION_ECDSA_WITH_SHA384 = X9ObjectIdentifiers.ecdsa_with_SHA384.getId();
    private static final String  ENCRYPTION_ECDSA_WITH_SHA512 = X9ObjectIdentifiers.ecdsa_with_SHA512.getId();

    private static final Set NO_PARAMS = new HashSet();
    private static final Map EC_ALGORITHMS = new HashMap();

    static
    {
        NO_PARAMS.add(ENCRYPTION_DSA);
        NO_PARAMS.add(ENCRYPTION_ECDSA);
        NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA1);
        NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA224);
        NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA256);
        NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA384);
        NO_PARAMS.add(ENCRYPTION_ECDSA_WITH_SHA512);

        EC_ALGORITHMS.put(DIGEST_SHA1, ENCRYPTION_ECDSA_WITH_SHA1);
        EC_ALGORITHMS.put(DIGEST_SHA224, ENCRYPTION_ECDSA_WITH_SHA224);
        EC_ALGORITHMS.put(DIGEST_SHA256, ENCRYPTION_ECDSA_WITH_SHA256);
        EC_ALGORITHMS.put(DIGEST_SHA384, ENCRYPTION_ECDSA_WITH_SHA384);
        EC_ALGORITHMS.put(DIGEST_SHA512, ENCRYPTION_ECDSA_WITH_SHA512);
    }

    protected CMSSignedGenerator()
    {
        
    }
    
    protected String getEncOID(
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
        else if ("ECDSA".equalsIgnoreCase(key.getAlgorithm()))
        {
            encOID = (String)EC_ALGORITHMS.get(digestOID);
            if (encOID == null)
            {
                throw new IllegalArgumentException("can't mix ECDSA with anything but SHA family digests");
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

    protected AlgorithmIdentifier getEncAlgorithmIdentifier(String encOid)
    {
        if (NO_PARAMS.contains(encOid))
        {
            return new AlgorithmIdentifier(
                  new DERObjectIdentifier(encOid));
        }
        else
        {
            return new AlgorithmIdentifier(
                  new DERObjectIdentifier(encOid), new DERNull());
        }
    }

    protected ASN1Set getSignedAttributeSet(
        DERObjectIdentifier contentType, 
        byte[]              hash, 
        AttributeTable      attr, 
        boolean             addDefaultAttributes)
    {
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
            
            ASN1EncodableVector attrs = attr.toASN1EncodableVector();
            
            for (int i = 0; i != attrs.size(); i++)
            {
                Attribute           a = Attribute.getInstance(attrs.get(i));
                DERObjectIdentifier type = a.getAttrType();
                
                if (type.equals(CMSAttributes.contentType)
                    || type.equals(CMSAttributes.signingTime)
                    || type.equals(CMSAttributes.messageDigest))
                {
                    continue;
                }
                
                v.add(a);
            }

            return new DERSet(v);
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

                return new DERSet(v);
            }
        }

        return null;
    }

    protected Map getBaseParameters(DERObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)
    {
        Map param = new HashMap();

        param.put(CMSAttributeTableGenerator.CONTENT_TYPE, contentType);
        param.put(CMSAttributeTableGenerator.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);

        if (hash != null)
        {
            param.put(CMSAttributeTableGenerator.DIGEST,  hash.clone());
        }

        return param;
    }

    protected ASN1Set getAttributeSet(
        AttributeTable attr)
    {
        if (attr != null)
        {
            return new DERSet(attr.toASN1EncodableVector());
        }
        
        return null;
    }
}
