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
import org.bouncycastle.pqc.jcajce.spec.McEliecePrivateKeySpec;

public class McEliecePrivateKey
    extends ASN1Object
{


    private McEliecePrivateKeySpec keySpec;
    ;

    public McEliecePrivateKey(McEliecePrivateKeySpec keySpec)
    {
        this.keySpec = keySpec;
    }

    public McEliecePrivateKey(ASN1Sequence seq)
    {
        // <oidString>
        String oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0)).getId();

        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        int n = bigN.intValue();

        BigInteger bigK = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        int k = bigK.intValue();

        byte[] encField = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        byte[] encGp = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

        byte[] encSInv = ((ASN1OctetString)seq.getObjectAt(5)).getOctets();

        byte[] encP1 = ((ASN1OctetString)seq.getObjectAt(6)).getOctets();

        byte[] encP2 = ((ASN1OctetString)seq.getObjectAt(7)).getOctets();

        byte[] encH = ((ASN1OctetString)seq.getObjectAt(8)).getOctets();

        ASN1Sequence asnQInv = (ASN1Sequence)seq.getObjectAt(9);
        byte[][] encqInv = new byte[asnQInv.size()][];
        for (int i = 0; i < asnQInv.size(); i++)
        {
            encqInv[i] = ((ASN1OctetString)asnQInv.getObjectAt(i)).getOctets();
        }

        keySpec = new McEliecePrivateKeySpec(oid, n, k, encField, encGp, encSInv, encP1, encP2, encH, encqInv);

    }

    public ASN1Primitive toASN1Primitive()
    {

        ASN1EncodableVector v = new ASN1EncodableVector();
        // encode <oidString>
        v.add(new ASN1ObjectIdentifier(keySpec.getOIDString()));
        // encode <n>
        v.add(new ASN1Integer(keySpec.getN()));

        // encode <k>
        v.add(new ASN1Integer(keySpec.getK()));

        // encode <fieldPoly>
        v.add(new DEROctetString(keySpec.getField().getEncoded()));

        // encode <goppaPoly>
        v.add(new DEROctetString(keySpec.getGoppaPoly().getEncoded()));

        // encode <sInv>
        v.add(new DEROctetString(keySpec.getSInv().getEncoded()));

        // encode <p1>
        v.add(new DEROctetString(keySpec.getP1().getEncoded()));

        // encode <p2>
        v.add(new DEROctetString(keySpec.getP2().getEncoded()));

        // encode <h>
        v.add(new DEROctetString(keySpec.getH().getEncoded()));

        // encode <q>
        ASN1EncodableVector asnQInv = new ASN1EncodableVector();
        for (int i = 0; i < keySpec.getQInv().length; i++)
        {
            asnQInv.add(new DEROctetString(keySpec.getQInv()[i].getEncoded()));
        }

        v.add(new DERSequence(asnQInv));

        return new DERSequence(v);
    }


    public McEliecePrivateKeySpec getKeySpec()
    {
        return this.keySpec;
    }
}
