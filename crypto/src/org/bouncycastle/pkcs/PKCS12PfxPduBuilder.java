package org.bouncycastle.pkcs;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.Pfx;
import org.bouncycastle.cms.CMSEncryptedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.operator.OutputEncryptor;

public class PKCS12PfxPduBuilder
{
    private ASN1EncodableVector dataVector = new ASN1EncodableVector();

    public PKCS12PfxPduBuilder addData(PKCS12SafeBag data)
        throws IOException
    {
        dataVector.add(new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(new DLSequence(data.toASN1Structure()).getEncoded())));

        return this;
    }

    public PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, PKCS12SafeBag data)
        throws IOException
    {
        return addEncryptedData(dataEncryptor, new DERSequence(data.toASN1Structure()));
    }

    public PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, PKCS12SafeBag[] data)
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != data.length; i++)
        {
            v.add(data[i].toASN1Structure());
        }

        return addEncryptedData(dataEncryptor, new DLSequence(v));
    }

    private PKCS12PfxPduBuilder addEncryptedData(OutputEncryptor dataEncryptor, ASN1Sequence data)
        throws IOException
    {
        CMSEncryptedDataGenerator envGen = new CMSEncryptedDataGenerator();

        try
        {
            dataVector.add(envGen.generate(new CMSProcessableByteArray(data.getEncoded()), dataEncryptor).toASN1Structure());
        }
        catch (CMSException e)
        {
            throw new PKCSIOException(e.getMessage(), e.getCause());
        }

        return this;
    }

    public PKCS12PfxPdu build(PKCS12MacCalculatorBuilder macCalcBuilder, char[] password)
        throws PKCSException
    {
        AuthenticatedSafe auth = AuthenticatedSafe.getInstance(new DLSequence(dataVector));
        byte[]            encAuth;

        try
        {
            encAuth = auth.getEncoded();
        }
        catch (IOException e)
        {
            throw new PKCSException("unable to encode AuthenticatedSafe: " + e.getMessage(), e);
        }

        ContentInfo       mainInfo = new ContentInfo(PKCSObjectIdentifiers.data, new DEROctetString(encAuth));
        MacData           mData = null;

        if (macCalcBuilder != null)
        {
            MacDataGenerator mdGen = new MacDataGenerator(macCalcBuilder);

            mData = mdGen.build(password, encAuth);
        }

        //
        // output the Pfx
        //
        Pfx pfx = new Pfx(mainInfo, mData);

        return new PKCS12PfxPdu(pfx);
    }
}
