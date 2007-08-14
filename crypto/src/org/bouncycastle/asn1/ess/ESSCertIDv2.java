package org.bouncycastle.asn1.ess;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class ESSCertIDv2
    extends ASN1Encodable
{
    private AlgorithmIdentifier hashAlgorithm;
    private byte[]              certHash;
    private IssuerSerial        issuerSerial;

    public static ESSCertIDv2 getInstance(
        Object o)
    {
        if (o == null || o instanceof ESSCertIDv2)
        {
            return (ESSCertIDv2) o;
        }
        else if (o instanceof ASN1Sequence)
        {
            return new ESSCertIDv2((ASN1Sequence) o);
        }

        throw new IllegalArgumentException(
                "unknown object in 'ESSCertIDv2' factory : "
                        + o.getClass().getName() + ".");
    }

    public ESSCertIDv2(
        ASN1Sequence seq)
    {
        if (seq.size() != 2 && seq.size() != 3)
        {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0).getDERObject());
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(1).getDERObject()).getOctets();

        if (seq.size() > 2)
        {
            this.issuerSerial = new IssuerSerial(ASN1Sequence.getInstance(seq.getObjectAt(2).getDERObject()));
        }
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash)
    {
        this(algId, certHash, null);
    }

    public ESSCertIDv2(
        AlgorithmIdentifier algId,
        byte[]              certHash,
        IssuerSerial        issuerSerial)
    {
        if (algId == null)
        {
            // Default value
            this.hashAlgorithm = new AlgorithmIdentifier(NISTObjectIdentifiers.dsa_with_sha256);
        }
        else
        {
            this.hashAlgorithm = algId;
        }

        this.certHash = certHash;
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return this.hashAlgorithm;
    }

    public byte[] getCertHash()
    {
        return certHash;
    }

    public IssuerSerial getIssuerSerial()
    {
        return issuerSerial;
    }

    /**
     * <pre>
     * ESSCertIDv2 ::=  SEQUENCE {
     *     hashAlgorithm     AlgorithmIdentifier
     *              DEFAULT {algorithm id-sha256 parameters NULL},
     *     certHash          Hash,
     *     issuerSerial      IssuerSerial OPTIONAL
     * }
     *
     * Hash ::= OCTET STRING
     *
     * IssuerSerial ::= SEQUENCE {
     *     issuer         GeneralNames,
     *     serialNumber   CertificateSerialNumber
     * }
     * </pre>
     */
    public DERObject toASN1Object()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(hashAlgorithm);

        v.add(new DEROctetString(certHash).toASN1Object());

        if (issuerSerial != null)
        {
            v.add(issuerSerial);
        }

        return new DERSequence(v);
    }

}
