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
 * SignedData ::= SEQUENCE {
 *     version CMSVersion,
 *     digestAlgorithms DigestAlgorithmIdentifiers,
 *     encapContentInfo EncapsulatedContentInfo,
 *     certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
 *     signerInfos SignerInfos
 *   }
 * </pre>
 * @deprecated use corresponding class in org.bouncycastle.asn1.cms
 */
public class SignedDataParser
{
    private Asn1Sequence         _seq;
    private Asn1Integer          _version;
    private Asn1Object           _nextObject;
    private boolean              _certsCalled;
    private boolean              _crlsCalled;
    
    public SignedDataParser(
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

    public Asn1Set getDigestAlgorithms() 
        throws IOException
    {
        return (Asn1Set)_seq.readObject();
    }

    public ContentInfoParser getEncapContentInfo()
        throws IOException
    {
        return new ContentInfoParser((Asn1Sequence)_seq.readObject());
    }

    public Asn1Set getCertificates() 
        throws IOException
    {
        _certsCalled = true;
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
        if (!_certsCalled)
        {
            throw new IOException("getCerts() has not been called.");
        }
        
        _crlsCalled = true;
        
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
    
    public Asn1Set getSignerInfos() 
        throws IOException
    {
        if (!_certsCalled || !_crlsCalled)
        {
            throw new IOException("getCerts() and/or getCrls() has not been called.");
        }
        
        if (_nextObject == null)
        {
            _nextObject = _seq.readObject();
        }
        
        return (Asn1Set)_nextObject;
    }
}
