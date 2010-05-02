package org.bouncycastle.cms;

import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchProviderException;
import java.security.Provider;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.AuthenticatedData;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/**
 * containing class for an CMS Authenticated Data object
 */
public class CMSAuthenticatedData
{
    RecipientInformationStore   recipientInfoStore;
    ContentInfo                 contentInfo;

    private AlgorithmIdentifier macAlg;
    private ASN1Set authAttrs;
    private ASN1Set unauthAttrs;
    private byte[] mac;

    public CMSAuthenticatedData(
        byte[]    authData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData));
    }

    public CMSAuthenticatedData(
        InputStream    authData)
        throws CMSException
    {
        this(CMSUtils.readContentInfo(authData));
    }

    public CMSAuthenticatedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;

        AuthenticatedData authData = AuthenticatedData.getInstance(contentInfo.getContent());

        //
        // read the recipients
        //
        ASN1Set recipientInfos = authData.getRecipientInfos();

        this.macAlg = authData.getMacAlgorithm();

        //
        // read the authenticated content info
        //
        ContentInfo encInfo = authData.getEncapsulatedContentInfo();
        CMSReadable readable = new CMSProcessableByteArray(
            ASN1OctetString.getInstance(encInfo.getContent()).getOctets());
        CMSSecureReadable secureReadable = new CMSEnvelopedHelper.CMSAuthenticatedSecureReadable(
            this.macAlg, readable);

        //
        // build the RecipientInformationStore
        //
        this.recipientInfoStore = CMSEnvelopedHelper.buildRecipientInformationStore(
            recipientInfos, secureReadable);

        this.authAttrs = authData.getAuthAttrs();
        this.mac = authData.getMac().getOctets();
        this.unauthAttrs = authData.getUnauthAttrs();
    }

    public byte[] getMac()
    {
        return Arrays.clone(mac);
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

    /**
     * return the object identifier for the content MAC algorithm.
     */
    public String getMacAlgOID()
    {
        return macAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded MAC algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getMacAlgParams()
    {
        try
        {
            return encodeObj(macAlg.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }

    /**
     * Return an AlgorithmParameters object giving the MAC parameters
     * used to digest the message content.
     *
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws org.bouncycastle.cms.CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     * @throws java.security.NoSuchProviderException if the provider cannot be found.
     */
    public AlgorithmParameters getMacAlgorithmParameters(
        String  provider)
    throws CMSException, NoSuchProviderException
    {
        return getMacAlgorithmParameters(CMSUtils.getProvider(provider));
    }

    /**
     * Return an AlgorithmParameters object giving the MAC parameters
     * used to digest the message content.
     *
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws org.bouncycastle.cms.CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     */
    public AlgorithmParameters getMacAlgorithmParameters(
        Provider provider)
    throws CMSException
    {
        return CMSEnvelopedHelper.INSTANCE.getEncryptionAlgorithmParameters(getMacAlgOID(), getMacAlgParams(), provider);
    }

    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return the ContentInfo
     */
    public ContentInfo getContentInfo()
    {
        return contentInfo;
    }

    /**
     * return a table of the digested attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getAuthAttrs()
    {
        if (authAttrs == null)
        {
            return null;
        }

        return new AttributeTable(authAttrs);
    }

    /**
     * return a table of the undigested attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnauthAttrs()
    {
        if (unauthAttrs == null)
        {
            return null;
        }

        return new AttributeTable(unauthAttrs);
    }

    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        return contentInfo.getEncoded();
    }
}
