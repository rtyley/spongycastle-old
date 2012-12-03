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
import org.bouncycastle.pqc.jcajce.spec.McElieceCCA2PrivateKeySpec;

public class McElieceCCA2PrivateKey
    extends ASN1Object
{

    private McElieceCCA2PrivateKeySpec keySpec;

    public McElieceCCA2PrivateKey(McElieceCCA2PrivateKeySpec keySpec)
    {
        this.keySpec = keySpec;
    }

    public McElieceCCA2PrivateKey(ASN1Sequence seq)
    {
        String oid = ((ASN1ObjectIdentifier)seq.getObjectAt(0)).getId();

        BigInteger bigN = ((ASN1Integer)seq.getObjectAt(1)).getValue();
        int n = bigN.intValue();

        BigInteger bigK = ((ASN1Integer)seq.getObjectAt(2)).getValue();
        int k = bigK.intValue();

        byte[] encField = ((ASN1OctetString)seq.getObjectAt(3)).getOctets();

        byte[] encGp = ((ASN1OctetString)seq.getObjectAt(4)).getOctets();

        byte[] encP = ((ASN1OctetString)seq.getObjectAt(5)).getOctets();

        byte[] encH = ((ASN1OctetString)seq.getObjectAt(6)).getOctets();

        ASN1Sequence asnQInv = (ASN1Sequence)seq.getObjectAt(7);
        byte[][] encqInv = new byte[asnQInv.size()][];
        for (int i = 0; i < asnQInv.size(); i++)
        {
            encqInv[i] = ((ASN1OctetString)asnQInv.getObjectAt(i)).getOctets();
        }

        keySpec = new McElieceCCA2PrivateKeySpec(oid, n, k, encField, encGp, encP, encH, encqInv);

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

        // encode <field>
        v.add(new DEROctetString(keySpec.getField().getEncoded()));

        // encode <gp>
        v.add(new DEROctetString(keySpec.getGoppaPoly().getEncoded()));

        // encode <p>
        v.add(new DEROctetString(keySpec.getP().getEncoded()));

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

    public McElieceCCA2PrivateKeySpec getKeySpec()
    {
        return this.keySpec;
    }

}
