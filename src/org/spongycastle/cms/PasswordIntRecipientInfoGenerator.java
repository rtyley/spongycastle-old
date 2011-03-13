package org.spongycastle.cms;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.DERObjectIdentifier;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.cms.PasswordRecipientInfo;
import org.spongycastle.asn1.cms.RecipientInfo;
import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;

class PasswordIntRecipientInfoGenerator
    implements IntRecipientInfoGenerator
{
    private AlgorithmIdentifier keyDerivationAlgorithm;
    private SecretKey keyEncryptionKey;

    PasswordIntRecipientInfoGenerator()
    {
    }

    void setKeyDerivationAlgorithm(AlgorithmIdentifier keyDerivationAlgorithm)
    {
        this.keyDerivationAlgorithm = keyDerivationAlgorithm;
    }

    void setKeyEncryptionKey(SecretKey keyEncryptionKey)
    {
        this.keyEncryptionKey = keyEncryptionKey;
    }

    public RecipientInfo generate(SecretKey contentEncryptionKey, SecureRandom random,
            Provider prov) throws GeneralSecurityException
    {
        // TODO Consider passing in the wrapAlgorithmOID instead

        CMSEnvelopedHelper helper = CMSEnvelopedHelper.INSTANCE;
        String wrapAlgName = helper.getRFC3211WrapperName(keyEncryptionKey.getAlgorithm());
        Cipher keyCipher = helper.createSymmetricCipher(wrapAlgName, prov);        
        keyCipher.init(Cipher.WRAP_MODE, keyEncryptionKey, random);
        byte[] encryptedKeyBytes = keyCipher.wrap(contentEncryptionKey);

        ASN1OctetString encryptedKey = new DEROctetString(encryptedKeyBytes);


        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DERObjectIdentifier(keyEncryptionKey.getAlgorithm()));
        v.add(new DEROctetString(keyCipher.getIV()));
        AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.id_alg_PWRI_KEK, new DERSequence(v));


        return new RecipientInfo(new PasswordRecipientInfo(keyDerivationAlgorithm,
            keyEncryptionAlgorithm, encryptedKey));
    }

}
