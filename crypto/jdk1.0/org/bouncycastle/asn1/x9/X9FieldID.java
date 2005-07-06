package org.bouncycastle.asn1.x9;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;

/**
 * ASN.1 def for Elliptic-Curve Field ID structure. See
 * X9.62, for further details.
 */
public class X9FieldID
    implements DEREncodable, X9ObjectIdentifiers
{
    private DERObjectIdentifier     id;
    private DERObject               parameters;

	public X9FieldID(
        DERObjectIdentifier id,
		BigInteger          primeP)
	{
        this.id = id;
        this.parameters = new DERInteger(primeP);
	}

    public X9FieldID(
        ASN1Sequence  seq)
    {
        this.id = (DERObjectIdentifier)seq.getObjectAt(0);
        this.parameters = (DERObject)seq.getObjectAt(1);
    }

    public DERObjectIdentifier getIdentifier()
    {
        return id;
    }

    public DERObject getParameters()
    {
        return parameters;
    }

    /**
     * <pre>
     *  FieldID ::= SEQUENCE {
     *      fieldType       FIELD-ID.&id({IOSet}),
     *      parameters      FIELD-ID.&Type({IOSet}{@fieldType})
     *  }
     * </pre>
     */
    public DERObject getDERObject()
    {
        ASN1EncodableVector seq = new ASN1EncodableVector();

        seq.add(this.id);
        seq.add(this.parameters);

        return new DERSequence(seq);
    }
}
