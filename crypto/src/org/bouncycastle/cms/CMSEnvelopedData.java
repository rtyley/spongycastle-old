package org.bouncycastle.cms;

import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EncryptedContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;

/**
 * containing class for an CMS Enveloped Data object
 */
public class CMSEnvelopedData
{
    RecipientInformationStore   recipientInfoStore;
    ContentInfo                 contentInfo;
    
    private AlgorithmIdentifier    encAlg;
    private ASN1Set                unprotectedAttributes;
    private AlgorithmIdentifier _encAlg;

    public CMSEnvelopedData(
        byte[]    envelopedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(envelopedData));
    }

    public CMSEnvelopedData(
        InputStream    envelopedData) 
        throws CMSException
    {
        this(CMSUtils.readContentInfo(envelopedData));
    }

    public CMSEnvelopedData(
        ContentInfo contentInfo)
        throws CMSException
    {
        this.contentInfo = contentInfo;

        EnvelopedData  envData = EnvelopedData.getInstance(contentInfo.getContent());

        //
        // read the encrypted content info
        //
        EncryptedContentInfo encInfo = envData.getEncryptedContentInfo();
        
        this._encAlg = encInfo.getContentEncryptionAlgorithm();
        
        //
        // load the RecepientInfoStore
        //
        ASN1Set     s = envData.getRecipientInfos();
        List        infos = new ArrayList();

        for (int i = 0; i != s.size(); i++)
        {
            RecipientInfo   info = RecipientInfo.getInstance(s.getObjectAt(i));
            Object          type = info.getInfo();

            if (type instanceof KeyTransRecipientInfo)
            {
                infos.add(new KeyTransRecipientInformation(
                            (KeyTransRecipientInfo)type, _encAlg, new ByteArrayInputStream(encInfo.getEncryptedContent().getOctets())));
            }
            else if (type instanceof KEKRecipientInfo)
            {
                infos.add(new KEKRecipientInformation(
                            (KEKRecipientInfo)type, _encAlg, new ByteArrayInputStream(encInfo.getEncryptedContent().getOctets())));
            }
            else if (type instanceof KeyAgreeRecipientInfo)
            {
                infos.add(new KeyAgreeRecipientInformation(
                            (KeyAgreeRecipientInfo)type, _encAlg, new ByteArrayInputStream(encInfo.getEncryptedContent().getOctets())));
            }
            else if (type instanceof PasswordRecipientInfo)
            {
                infos.add(new PasswordRecipientInformation(
                            (PasswordRecipientInfo)type, _encAlg, new ByteArrayInputStream(encInfo.getEncryptedContent().getOctets())));
            }
        }

        this.encAlg = envData.getEncryptedContentInfo().getContentEncryptionAlgorithm();
        this.recipientInfoStore = new RecipientInformationStore(infos);
        this.unprotectedAttributes = envData.getUnprotectedAttrs();
    }

    private byte[] encodeObj(
        DEREncodable    obj)
        throws IOException
    {
        if (obj != null)
        {
            ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
            ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

            aOut.writeObject(obj);

            return bOut.toByteArray();
        }

        return null;
    }
    
    /**
     * return the object identifier for the content encryption algorithm.
     */
    public String getEncryptionAlgOID()
    {
        return encAlg.getObjectId().getId();
    }

    /**
     * return the ASN.1 encoded encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams()
    {
        try
        {
            return encodeObj(encAlg.getParameters());
        }
        catch (Exception e)
        {
            throw new RuntimeException("exception getting encryption parameters " + e);
        }
    }
    
    /**
     * Return an AlgorithmParameters object giving the encryption parameters
     * used to encrypt the message content.
     * 
     * @param provider the provider to generate the parameters for.
     * @return the parameters object, null if there is not one.
     * @throws CMSException if the algorithm cannot be found, or the parameters can't be parsed.
     * @throws NoSuchProviderException if the provider cannot be found.
     */
    public AlgorithmParameters getEncryptionAlgorithmParameters(
            String  provider) 
    throws CMSException, NoSuchProviderException    
    {        
        try
        {
            byte[]  enc = this.encodeObj(encAlg.getParameters());
            if (enc == null)
            {
                return null;
            }
            
            AlgorithmParameters params = AlgorithmParameters.getInstance(getEncryptionAlgOID(), provider); 
            
            params.init(enc, "ASN.1");
            
            return params;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find parameters for algorithm", e);
        }
        catch (IOException e)
        {
            throw new CMSException("can't find parse parameters", e);
        }  
    }
    
    /**
     * return a store of the intended recipients for this message
     */
    public RecipientInformationStore getRecipientInfos()
    {
        return recipientInfoStore;
    }

    /**
     * return a table of the unprotected attributes indexed by
     * the OID of the attribute.
     */
    public AttributeTable getUnprotectedAttributes()
    {
        if (unprotectedAttributes == null)
        {
            return null;
        }

        return new AttributeTable(unprotectedAttributes);
    }
    
    /**
     * return the ASN.1 encoded representation of this object.
     */
    public byte[] getEncoded()
        throws IOException
    {
        ByteArrayOutputStream   bOut = new ByteArrayOutputStream();
        ASN1OutputStream        aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(contentInfo);

        return bOut.toByteArray();
    }
}
