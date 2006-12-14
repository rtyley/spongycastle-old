package org.bouncycastle.sasn1.cms;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.sasn1.Asn1Integer;
import org.bouncycastle.sasn1.Asn1Sequence;
import org.bouncycastle.sasn1.DerSequence;

import java.io.IOException;

/** 
 * RFC 3274 - CMS Compressed Data.
 * <pre>
 * CompressedData ::= SEQUENCE {
 *  version CMSVersion,
 *  compressionAlgorithm CompressionAlgorithmIdentifier,
 *  encapContentInfo EncapsulatedContentInfo
 * }
 * </pre>
 * @deprecated use corresponding class in org.bouncycastle.asn1.cms
 */
public class CompressedDataParser
{
    private Asn1Integer          _version;
    private AlgorithmIdentifier  _compressionAlgorithm;
    private ContentInfoParser    _encapContentInfo;
    
    public CompressedDataParser(
        Asn1Sequence seq)
        throws IOException
    {
        this._version = (Asn1Integer)seq.readObject();
        this._compressionAlgorithm = AlgorithmIdentifier.getInstance(new ASN1InputStream(((DerSequence)seq.readObject()).getEncoded()).readObject());
        this._encapContentInfo = new ContentInfoParser((Asn1Sequence)seq.readObject());
    }

    public Asn1Integer getVersion()
    {
        return _version;
    }

    public AlgorithmIdentifier getCompressionAlgorithmIdentifier()
    {
        return _compressionAlgorithm;
    }

    public ContentInfoParser getEncapContentInfo()
    {
        return _encapContentInfo;
    }
}
