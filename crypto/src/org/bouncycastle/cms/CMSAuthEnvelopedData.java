package org.bouncycastle.cms;

import java.io.InputStream;
import java.util.List;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AuthEnvelopedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.OriginatorInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * containing class for an CMS AuthEnveloped Data object
 */
class CMSAuthEnvelopedData
{
    RecipientInformationStore recipientInfoStore;
    ContentInfo contentInfo;

    private OriginatorInfo      originator;
    private AlgorithmIdentifier authEncAlg;
    private ASN1Set             authAttrs;
    private byte[]              mac;
    private ASN1Set             unauthAttrs;

    public CMSAuthEnvelopedData(byte[] authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(InputStream authEnvData) throws CMSException
    {
        this(CMSUtils.readContentInfo(authEnvData));
    }

    public CMSAuthEnvelopedData(ContentInfo contentInfo) throws CMSException
    {
        this.contentInfo = contentInfo;

        AuthEnvelopedData authEnvData = AuthEnvelopedData.getInstance(contentInfo.getContent());

        this.originator = authEnvData.getOriginatorInfo();

        //
        // read the encrypted content info
        //
        EncryptedContentInfo authEncInfo = authEnvData.getAuthEncryptedContentInfo();

        this.authEncAlg = authEncInfo.getContentEncryptionAlgorithm();

        //
        // load the RecipientInfoStore
        //
        byte[] contentOctets = authEncInfo.getEncryptedContent().getOctets();
        List infos = CMSEnvelopedHelper.readRecipientInfos(
            authEnvData.getRecipientInfos(), contentOctets, null, null, authEncAlg);
        this.recipientInfoStore = new RecipientInformationStore(infos);

        // FIXME These need to be passed to the AEAD cipher as AAD (Additional Authenticated Data)
        this.authAttrs = authEnvData.getAuthAttrs();

        this.mac = authEnvData.getMac().getOctets();

        this.unauthAttrs = authEnvData.getUnauthAttrs();
    }
}
