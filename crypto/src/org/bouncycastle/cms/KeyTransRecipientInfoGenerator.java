package org.bouncycastle.cms;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

public abstract class KeyTransRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    // Derived fields
    protected final SubjectPublicKeyInfo keyInfo;

    private IssuerAndSerialNumber issuerAndSerial;
    private byte[] subjectKeyIdentifier;

    private KeyTransRecipientInfoGenerator(SubjectPublicKeyInfo keyInfo, IssuerAndSerialNumber issuerAndSerial)
    {
        this.keyInfo = keyInfo;
        this.issuerAndSerial = issuerAndSerial;
    }

    protected KeyTransRecipientInfoGenerator(X509CertificateHolder certHolder)
    {
        this(certHolder.getSubjectPublicKeyInfo(), certHolder.getIssuerAndSerialNumber());
    }

    protected KeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, SubjectPublicKeyInfo keyInfo)
    {
        this.subjectKeyIdentifier = subjectKeyIdentifier;
        this.keyInfo = keyInfo;
    }

    public final RecipientInfo generate(byte[] contentEncryptionKey)
        throws CMSException
    {

        byte[] encryptedKeyBytes = generateEncryptedBytes(keyInfo.getAlgorithmId(), contentEncryptionKey);

        RecipientIdentifier recipId;
        if (issuerAndSerial != null)
        {
            recipId = new RecipientIdentifier(issuerAndSerial);
        }
        else
        {
            recipId = new RecipientIdentifier(new DEROctetString(subjectKeyIdentifier));
        }

        return new RecipientInfo(new KeyTransRecipientInfo(recipId, keyInfo.getAlgorithmId(),
            new DEROctetString(encryptedKeyBytes)));
    }

    protected abstract byte[] generateEncryptedBytes(AlgorithmIdentifier algorithm, byte[] contentEncryptionKey)
        throws CMSException;
}