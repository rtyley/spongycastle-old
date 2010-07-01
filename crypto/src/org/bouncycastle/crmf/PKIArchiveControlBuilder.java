package org.bouncycastle.crmf;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;

public class PKIArchiveControlBuilder
{
    private CMSEnvelopedDataGenerator envGen;
    private CMSProcessableByteArray keyContent;

    public PKIArchiveControlBuilder(PrivateKey privateKey, X500Principal name)
    {
        this(privateKey, new GeneralName(X509Name.getInstance(name.getEncoded())));
    }

    public PKIArchiveControlBuilder(PrivateKey privateKey, GeneralName generalName)
    {
        EncKeyWithID encKeyWithID = new EncKeyWithID(PrivateKeyInfo.getInstance(privateKey.getEncoded()), generalName);

        try
        {
            this.keyContent = new CMSProcessableByteArray(CRMFObjectIdentifiers.id_ct_encKeyWithID, encKeyWithID.getEncoded());
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode key and general name info");
        }

        this.envGen = new CMSEnvelopedDataGenerator();
    }

    public PKIArchiveControlBuilder addKEKRecipent(SecretKey secretKey, byte[] keyIdentifier)
    {
        envGen.addKEKRecipient(secretKey, keyIdentifier);

        return this;
    }

    public PKIArchiveControlBuilder addKeyTransRecipient(X509Certificate cert)
    {
        envGen.addKeyTransRecipient(cert);

        return this;
    }

    public PKIArchiveControl build(String encAlgorithm, String prov)
        throws CMSException, NoSuchAlgorithmException, NoSuchProviderException
    {
        CMSEnvelopedData envContent = envGen.generate(keyContent, encAlgorithm, prov);

        return createControl(envContent);
    }

    public PKIArchiveControl build(String encAlgorithm, Provider prov)
        throws CMSException, NoSuchAlgorithmException
    {
        CMSEnvelopedData envContent = envGen.generate(keyContent, encAlgorithm, prov);

        return createControl(envContent);
    }

    private PKIArchiveControl createControl(CMSEnvelopedData envContent)
    {
        EnvelopedData envD = EnvelopedData.getInstance(envContent.getContentInfo().getContent());

        return new PKIArchiveControl(new PKIArchiveOptions(new EncryptedKey(envD)));
    }
}
