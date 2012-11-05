package org.bouncycastle.pqc.asn1;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2PublicKeySpec;

public class McElieceCCA2PublicKey
    extends ASN1Object
{
    private McElieceCCA2PublicKeySpec keySpec;

    public McElieceCCA2PublicKey(McElieceCCA2PublicKeySpec keySpec)
    {
        this.keySpec = keySpec;
    }

    public McElieceCCA2PublicKey(ASN1Sequence seq)
    {
        String oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0)).getId();
        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        int n = bigN.intValue();

        BigInteger bigT = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        int t = bigT.intValue();

        byte[] matrixG = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        keySpec = new McElieceCCA2PublicKeySpec(oid, n, t, matrixG);
    }

    @Override
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();
        // encode <oidString>
        v.add(new ASN1ObjectIdentifier(keySpec.getOIDString()));

        // encode <n>
        v.add(new ASN1Integer(keySpec.getN()));

        // encode <t>
        v.add(new ASN1Integer(keySpec.getT()));

        // encode <matrixG>
        v.add(new DEROctetString(keySpec.getMatrixG().getEncoded()));

        return new DERSequence(v);
    }

    public McElieceCCA2PublicKeySpec getKeySpec()
    {
        return this.keySpec;
    }
}
