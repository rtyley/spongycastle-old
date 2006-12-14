package org.bouncycastle.sasn1.cms;

import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1Object;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.Asn1Set;
import org.bouncycastle.sasn1.Asn1TaggedObject;
import org.bouncycastle.sasn1.BerTag;

import java.io.IOException;

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
 * @deprecated use corresponding class in org.bouncycastle.asn1.cms
 */
public class EnvelopedDataParser
{
    private Asn1Sequence         _seq;
    private Asn1Integer          _version;
    private Asn1Object           _nextObject;
    
    public EnvelopedDataParser(
        Asn1Sequence seq)
        throws IOException
    {
        this._seq = seq;
        this._version = (Asn1Integer)seq.readObject();
    }

    public Asn1Integer getVersion()
    {
        return _version;
    }

    public Asn1Set getCertificates() 
        throws IOException
    {
        _nextObject = _seq.readObject();

        if (_nextObject instanceof Asn1TaggedObject && ((Asn1TaggedObject)_nextObject).getTagNumber() == 0)
        {
            Asn1Set certs = (Asn1Set)((Asn1TaggedObject)_nextObject).getObject(BerTag.SET, false);
            _nextObject = null;
            
            return certs;
        }
        
        return null;
    }
    
    public Asn1Set getCrls() 
        throws IOException
    {
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        if (_nextObject instanceof Asn1TaggedObject && ((Asn1TaggedObject)_nextObject).getTagNumber() == 1)
        {
            Asn1Set crls = (Asn1Set)((Asn1TaggedObject)_nextObject).getObject(BerTag.SET, false);
            _nextObject = null;
            
            return crls;
        }
        
        return null;
    }

    public Asn1Set getRecipientInfos() 
        throws IOException
    {
        return (Asn1Set)_seq.readObject();
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() 
        throws IOException
    {
        return new EncryptedContentInfoParser((Asn1Sequence)_seq.readObject());
    }

    public Asn1Set getUnprotectedAttrs() 
        throws IOException
    {
        Asn1Object o = _seq.readObject();
        
        if (o != null)
        {
            return (Asn1Set)((Asn1TaggedObject)o).getObject(BerTag.SET, false);
        }
        
        return null;
    }
}
