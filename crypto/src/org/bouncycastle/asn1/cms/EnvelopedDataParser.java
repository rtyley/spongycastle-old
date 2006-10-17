package org.bouncycastle.asn1.cms;

import java.io.IOException;

import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.DERTags;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;

/** 
 * <pre>
 * EnvelopedData ::= SEQUENCE {
 *     version CMSVersion,
 *     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *     recipientInfos RecipientInfos,
 *     encryptedContentInfo EncryptedContentInfo,
 *     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL 
 * }
 * </pre>
 */
public class EnvelopedDataParser
{
    private ASN1SequenceParser _seq;
    private DERInteger         _version;
    private DEREncodable       _nextObject;
    
    public EnvelopedDataParser(
        ASN1SequenceParser seq)
        throws IOException
    {
        this._seq = seq;
        this._version = (DERInteger)seq.readObject();
    }

    public DERInteger getVersion()
    {
        return _version;
    }

    public ASN1SetParser getCertificates() 
        throws IOException
    {
        _nextObject = _seq.readObject();

        if (_nextObject instanceof ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 0)
        {
            ASN1SetParser certs = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(DERTags.SET, false);
            _nextObject = null;
            
            return certs;
        }
        
        return null;
    }
    
    public ASN1SetParser getCrls() 
        throws IOException
    {
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        if (_nextObject instanceof ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 1)
        {
            ASN1SetParser crls = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(DERTags.SET, false);
            _nextObject = null;
            
            return crls;
        }
        
        return null;
    }

    public ASN1SetParser getRecipientInfos()
        throws IOException
    {
        return (ASN1SetParser)_seq.readObject();
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() 
        throws IOException
    {
        return new EncryptedContentInfoParser((ASN1SequenceParser)_seq.readObject());
    }

    public ASN1SetParser getUnprotectedAttrs()
        throws IOException
    {
        DEREncodable o = _seq.readObject();
        
        if (o != null)
        {
            return (ASN1SetParser)((ASN1TaggedObjectParser)o).getObjectParser(DERTags.SET, false);
        }
        
        return null;
    }
}
