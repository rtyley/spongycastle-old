package org.bouncycastle.cms;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.KEKRecipientInfo;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.sasn1.Asn1Object;
import org.bouncycastle.sasn1.Asn1OctetString;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.Asn1Set;
import org.bouncycastle.sasn1.Asn1TaggedObject;
import org.bouncycastle.sasn1.BerTag;
import org.bouncycastle.sasn1.DerObject;
import org.bouncycastle.sasn1.DerSequence;
import org.bouncycastle.sasn1.cms.ContentInfoParser;
import org.bouncycastle.sasn1.cms.EncryptedContentInfoParser;
import org.bouncycastle.sasn1.cms.EnvelopedDataParser;

/**
 * Parsing class for an CMS Enveloped Data object from an input stream.
 * <p>
 * Note: that because we are in a streaming mode only one recipient can be tried and it is important 
 * that the methods on the parser are called in the appropriate order.
 * </p>
 * <p>
 * Example of use - assuming the first recipient matches the private key we have.
 * <pre>
 *      CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(inputStream);
 *
 *      RecipientInformationStore  recipients = ep.getRecipientInfos();
 *
 *      Collection  c = recipients.getRecipients();
 *      Iterator    it = c.iterator();
 *      
 *      if (it.hasNext())
 *      {
 *          RecipientInformation   recipient = (RecipientInformation)it.next();
 *
 *          CMSTypedStream recData = recipient.getContentStream(privateKey, "BC");
 *          
 *          processDataStream(recData.getContentStream());
 *      }
 *  </pre>
 *  Note: this class does not introduce buffering - if you are processing large files you should create
 *  the parser with:
 *  <pre>
 *          CMSEnvelopedDataParser     ep = new CMSEnvelopedDataParser(new BufferedInputStream(inputStream, bufSize));
 *  </pre>
 *  where bufSize is a suitably large buffer size.
 */
public class CMSEnvelopedDataParser
    extends CMSContentInfoParser
{
    RecipientInformationStore   _recipientInfoStore;
    EnvelopedDataParser         _envelopedData;
    
    private AlgorithmIdentifier _encAlg;
    private AttributeTable      _unprotectedAttributes;
    private boolean             _attrNotRead;

    public CMSEnvelopedDataParser(
        byte[]    envelopedData) 
        throws CMSException, IOException
    {
        this(readContentInfo(new ByteArrayInputStream(envelopedData)));
    }

    public CMSEnvelopedDataParser(
        InputStream    envelopedData) 
        throws CMSException, IOException
    {
        this(readContentInfo(envelopedData));
    }

    CMSEnvelopedDataParser(
        ContentInfoParser contentInfo)
        throws CMSException, IOException
    {
        super(contentInfo);

        this._attrNotRead = true;
        this._envelopedData = new EnvelopedDataParser((Asn1Sequence)_contentInfo.getContent(BerTag.SEQUENCE));

        //
        // load the RecepientInfoStore
        //
        Asn1Set     s = _envelopedData.getRecipientInfos();
        List        baseInfos = new ArrayList();
        Asn1Object  o = null;
        
        while ((o = s.readObject()) != null)
        {
            if (o instanceof DerSequence)
            {
                DerSequence     seq = (DerSequence)o;
    
                baseInfos.add(RecipientInfo.getInstance(new ASN1InputStream(seq.getEncoded()).readObject()));
            }
            else 
            {
                Asn1TaggedObject t = (Asn1TaggedObject)o;
                DerSequence      seq = (DerSequence)t.getObject(BerTag.SEQUENCE, true);
                
                baseInfos.add(RecipientInfo.getInstance(new DERTaggedObject(true, t.getTagNumber(), new ASN1InputStream(seq.getEncoded()).readObject())));
            }
        }

        //
        // read the encrypted content info
        //
        EncryptedContentInfoParser encInfo = _envelopedData.getEncryptedContentInfo();
        
        this._encAlg = encInfo.getContentEncryptionAlgorithm();
        
        //
        // prime the recepients
        //
        List      infos = new ArrayList();
        Iterator  it = baseInfos.iterator();
        
        while (it.hasNext())
        {
            RecipientInfo   info = (RecipientInfo)it.next();

            if (info.getInfo() instanceof KeyTransRecipientInfo)
            {
                infos.add(new KeyTransRecipientInformation(
                            (KeyTransRecipientInfo)info.getInfo(), _encAlg, ((Asn1OctetString)encInfo.getEncryptedContent(BerTag.OCTET_STRING)).getOctetStream()));
            }
            else if (info.getInfo() instanceof KEKRecipientInfo)
            {
                infos.add(new KEKRecipientInformation(
                            (KEKRecipientInfo)info.getInfo(), _encAlg, ((Asn1OctetString)encInfo.getEncryptedContent(BerTag.OCTET_STRING)).getOctetStream()));
            }
        }
        
        _recipientInfoStore = new RecipientInformationStore(infos);
    }
    
    /**
     * return the object identifier for the content encryption algorithm.
     */
    public String getEncryptionAlgOID()
    {
        return _encAlg.getObjectId().toString();
    }

    /**
     * return the ASN.1 encoded encryption algorithm parameters, or null if
     * there aren't any.
     */
    public byte[] getEncryptionAlgParams()
    {
        try
        {
            return ((DerObject)_encAlg.getParameters()).getEncoded();
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
            byte[]  enc = this.getEncryptionAlgParams();
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
        return _recipientInfoStore;
    }

    /**
     * return a table of the unprotected attributes indexed by
     * the OID of the attribute.
     * @throws IOException 
     */
    public AttributeTable getUnprotectedAttributes() 
        throws IOException
    {
        if (_unprotectedAttributes == null && _attrNotRead)
        {
            Asn1Set             set = _envelopedData.getUnprotectedAttrs();
            
            _attrNotRead = false;
            
            if (set != null)
            {
                ASN1EncodableVector v = new ASN1EncodableVector();
                Asn1Object          o;
                
                while ((o = set.readObject()) != null)
                {
                    DerSequence     seq = (DerSequence)o;
                    
                    v.add(DERSequence.getInstance(new ASN1InputStream(seq.getEncoded()).readObject()));
                }
                
                _unprotectedAttributes = new AttributeTable(new DERSet(v));
            }
        }

        return _unprotectedAttributes;
    }
}
