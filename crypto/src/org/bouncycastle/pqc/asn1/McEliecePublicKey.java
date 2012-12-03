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
import org.bouncycastle.pqc.jcajce.spec.McEliecePublicKeySpec;

public class McEliecePublicKey extends ASN1Object{

	private McEliecePublicKeySpec keySpec;;

	public McEliecePublicKey(McEliecePublicKeySpec keySpec) {
		this.keySpec = keySpec;
	}

	public McEliecePublicKey(ASN1Sequence seq) {
		String oid = ((ASN1ObjectIdentifier) seq.getObjectAt(0)).getId();
		BigInteger bigN = ((ASN1Integer) seq.getObjectAt(1)).getValue();
		int n = bigN.intValue();

		BigInteger bigT = ((ASN1Integer) seq.getObjectAt(2)).getValue();
		int t = bigT.intValue();

		byte[] matrixG = ((ASN1OctetString) seq.getObjectAt(3)).getOctets();

		keySpec = new McEliecePublicKeySpec(oid, t, n, matrixG);

	}

	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		// encode <oidString>
		v.add(new ASN1ObjectIdentifier(keySpec.getOIDString()));
		// encode <n>
		v.add(new ASN1Integer(keySpec.getN()));

		// encode <t>
		v.add(new ASN1Integer(keySpec.getT()));

		// encode <matrixG>
		v.add(new DEROctetString(keySpec.getG().getEncoded()));

		return new DERSequence(v);
	}

	public McEliecePublicKeySpec getKeySpec(){
		return this.keySpec;
	}

}
