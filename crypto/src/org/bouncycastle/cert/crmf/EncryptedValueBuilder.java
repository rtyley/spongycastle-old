package org.bouncycastle.cert.crmf;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OutputEncryptor;

public class EncryptedValueBuilder
{
    private byte[] content;

    public EncryptedValue build(OutputEncryptor contentEncryptor)
        throws CMSException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new DERTaggedObject(false, 1, contentEncryptor.getAlgorithmIdentifier()));
        v.add(new DERTaggedObject(false, 2, new DERBitString(contentEncryptor.getEncodedKey())));

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        OutputStream eOut = contentEncryptor.getOutputStream(bOut);
//
//        eOut.write(content);
//
//        eOut.close();

        return EncryptedValue.getInstance(new DERSequence(v));
    }
}
