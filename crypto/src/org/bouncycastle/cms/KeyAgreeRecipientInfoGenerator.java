package org.bouncycastle.cms;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
import org.bouncycastle.asn1.cms.RecipientEncryptedKey;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.TBSCertificateStructure;

class KeyAgreeRecipientInfoGenerator implements RecipientInfoGenerator
{
    private DERObjectIdentifier algorithmOID;
    private OriginatorIdentifierOrKey originator;
    // TODO Pass recipId, keyEncAlg instead?
    private TBSCertificateStructure recipientTBSCert;
    private ASN1OctetString ukm;
    private DERObjectIdentifier wrapAlgorithmOID;
    private SecretKey wrapKey;

    KeyAgreeRecipientInfoGenerator()
    {
    }

    void setAlgorithmOID(DERObjectIdentifier algorithmOID)
    {
        this.algorithmOID = algorithmOID;
    }

    void setOriginator(OriginatorIdentifierOrKey originator)
    {
        this.originator = originator;
    }

    void setRecipientCert(X509Certificate recipientCert)
    {
        try
        {
            this.recipientTBSCert = CMSUtils.getTBSCertificateStructure(recipientCert);
        }
        catch (CertificateEncodingException e)
        {
            throw new IllegalArgumentException(
                    "can't extract TBS structure from this cert");
        }
    }

    void setUKM(ASN1OctetString ukm)
    {
        this.ukm = ukm;
    }

    void setWrapAlgorithmOID(DERObjectIdentifier wrapAlgorithmOID)
    {
        this.wrapAlgorithmOID = wrapAlgorithmOID;
    }

    void setWrapKey(SecretKey wrapKey)
    {
        this.wrapKey = wrapKey;
    }

    public RecipientInfo generate(SecretKey key, SecureRandom random,
            Provider prov) throws GeneralSecurityException
    {
        ASN1EncodableVector params = new ASN1EncodableVector();
        params.add(wrapAlgorithmOID);
        params.add(DERNull.INSTANCE);
        AlgorithmIdentifier keyEncAlg = new AlgorithmIdentifier(algorithmOID,
                new DERSequence(params));

        IssuerAndSerialNumber issuerSerial = new IssuerAndSerialNumber(
                recipientTBSCert.getIssuer(), recipientTBSCert.getSerialNumber()
                        .getValue());

        Cipher keyCipher = CMSEnvelopedHelper.INSTANCE.createAsymmetricCipher(
                wrapAlgorithmOID.getId(), prov);
        // TODO Should we try alternate ways of wrapping?
        //   (see KeyTransRecipientInfoGenerator.generate)
        keyCipher.init(Cipher.WRAP_MODE, wrapKey, random);
        ASN1OctetString encKey = new DEROctetString(keyCipher.wrap(key));

        RecipientEncryptedKey rKey = new RecipientEncryptedKey(
                new KeyAgreeRecipientIdentifier(issuerSerial),
                encKey);

        return new RecipientInfo(new KeyAgreeRecipientInfo(originator, ukm,
                keyEncAlg, new DERSequence(rKey)));
    }
}
