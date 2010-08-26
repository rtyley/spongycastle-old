package org.bouncycastle.cert.crmf;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.PKIArchiveOptions;
import org.bouncycastle.cms.CMSEnvelopedData;

public class PKIArchiveControl
    implements Control
{
    public static final int encryptedPrivKey = PKIArchiveOptions.encryptedPrivKey;
    public static final int keyGenParameters = PKIArchiveOptions.keyGenParameters;
    public static final int archiveRemGenPrivKey = PKIArchiveOptions.archiveRemGenPrivKey;

    private static final ASN1ObjectIdentifier type = CRMFObjectIdentifiers.id_regCtrl_pkiArchiveOptions;

    private final PKIArchiveOptions pkiArchiveOptions;

    public PKIArchiveControl(PKIArchiveOptions pkiArchiveOptions)
    {
        this.pkiArchiveOptions = pkiArchiveOptions;
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public ASN1Encodable getValue()
    {
        return pkiArchiveOptions;
    }

    public int getArchiveType()
    {
        return pkiArchiveOptions.getType();
    }

    public boolean isEnvelopedData()
    {
        EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());

        return !encKey.isEncryptedValue();
    }

    public CMSEnvelopedData getEnvelopedData()
    {
        EncryptedKey encKey = EncryptedKey.getInstance(pkiArchiveOptions.getValue());
        EnvelopedData data = EnvelopedData.getInstance(encKey.getValue());
        
        return new CMSEnvelopedData(new ContentInfo(CMSObjectIdentifiers.envelopedData, data));
    }
}
