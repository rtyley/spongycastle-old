package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;


/**
 * an Iso7816RSAPublicKeyStructure structure.
 * <p/>
 * <pre>
 *  Certificate Holder Authorization ::= SEQUENCE {
 *  	// modulus should be at least 1024bit and a multiple of 512.
 *  	DERTaggedObject		modulus,
 *  	// access rights	exponent
 *  	DERTaggedObject	accessRights,
 *  }
 * </pre>
 */
public class RSAPublicKey
    extends PublicKeyDataObject
{
    private ASN1ObjectIdentifier usage;
    private BigInteger modulus;
    private BigInteger exponent;
    private int valid = 0;
    private static int modulusValid = 0x01;
    private static int exponentValid = 0x02;

    RSAPublicKey(ASN1Sequence seq)
        throws IOException
    {
        Enumeration en = seq.getObjects();

        this.usage = (ASN1ObjectIdentifier)ASN1ObjectIdentifier.getInstance(en.nextElement());

        // TODO: add later
//        if (!SignatureType.isRSA(type))
//        {
//            throw new IllegalArgumentException("Not an RSA object");
//        }
//
        while (en.hasMoreElements())
        {
            UnsignedInteger val = UnsignedInteger.getInstance(en.nextElement());

            switch (val.getTagNo())
            {
            case 0x1:
                setModulus(val);
                break;
            case 0x2:
                setExponent(val);
                break;
            default:
                throw new IOException("Unknown DERTaggedObject :" + val.getTagNo() + "-> not an Iso7816RSAPublicKeyStructure");
            }
        }
        if (valid != 0x3)
        {
            throw new IOException("missing argument -> not an Iso7816RSAPublicKeyStructure");
        }
    }

    public RSAPublicKey(BigInteger modulus, BigInteger exponent)
        throws IOException
    {
        this.modulus = modulus;
        this.exponent = exponent;
    }



    public ASN1ObjectIdentifier getUsage()
    {
        return usage;
    }

    public BigInteger getModulus()
    {
        return modulus;
    }

    public BigInteger getPublicExponent()
    {
        return exponent;
    }

    private void setModulus(UnsignedInteger modulus)
        throws IOException
    {
        if ((valid & modulusValid) == 0)
        {
            valid |= modulusValid;
            this.modulus = modulus.getValue();
        }
        else
        {
            throw new IOException("Modulus already set");
        }
    }

    private void setExponent(UnsignedInteger exponent)
        throws IOException
    {
        if ((valid & exponentValid) == 0)
        {
            valid |= exponentValid;
            this.exponent = exponent.getValue();
        }
        else
        {
            throw new IOException("Exponent already set");
        }
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(usage);
        v.add(new UnsignedInteger(modulusValid, getModulus()));
        v.add(new UnsignedInteger(exponentValid, getPublicExponent()));

        return new DERSequence(v);
    }
}
