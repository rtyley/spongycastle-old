package org.bouncycastle.cms;

import java.security.SecureRandom;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class PasswordRecipientInfoGenerator
    implements RecipientInfoGenerator
{
    private AlgorithmIdentifier keyDerivationAlgorithm;
    private ASN1ObjectIdentifier kekAlgorithm;
    private SecureRandom random;

    protected PasswordRecipientInfoGenerator(AlgorithmIdentifier keyDerivationAlgorithm, ASN1ObjectIdentifier kekAlgorithm, SecureRandom random)
    {
        this.keyDerivationAlgorithm = keyDerivationAlgorithm;
        this.kekAlgorithm = kekAlgorithm;
        this.random = random;
    }

    public RecipientInfo generate(byte[] contentEncryptionKey)
        throws CMSException
    {
        byte[] iv = new byte[8];     /// TODO: set IV size properly!

        random.nextBytes(iv);

        AlgorithmIdentifier kekAlgorithmId = new AlgorithmIdentifier(kekAlgorithm, new DEROctetString(iv));

        byte[] encryptedKeyBytes = generateEncryptedBytes(kekAlgorithmId, contentEncryptionKey);

        ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(kekAlgorithm);
        v.add(new DEROctetString(iv));

        AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_alg_PWRI_KEK, new DERSequence(v));

        return new RecipientInfo(new PasswordRecipientInfo(keyDerivationAlgorithm,
            keyEncryptionAlgorithm, encryptedKey));
    }

    protected abstract byte[] generateEncryptedBytes(AlgorithmIdentifier algorithm, byte[] contentEncryptionKey)
        throws CMSException;
}