package org.bouncycastle.cert.crmf;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.KeyWrapper;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.OutputEncryptor;

public class EncryptedValueBuilder
{
    private X509CertificateHolder holder;
    private KeyWrapper wrapper;
    private OutputEncryptor encryptor;

    public EncryptedValueBuilder(X509CertificateHolder holder, KeyWrapper wrapper, OutputEncryptor encryptor)
    {
        this.holder = holder;
        this.wrapper = wrapper;
        this.encryptor = encryptor;
    }
    
    public EncryptedValue build()
        throws CRMFException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream eOut = encryptor.getOutputStream(bOut);

        try
        {
            eOut.write(holder.getEncoded());

            eOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("cannot process data: " + e.getMessage(), e);
        }

        AlgorithmIdentifier intendedAlg = null;
        AlgorithmIdentifier symmAlg = encryptor.getAlgorithmIdentifier();
        DERBitString encSymmKey;

        try
        {
            wrapper.generateWrappedKey(encryptor.getEncodedKey());
            encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getEncodedKey()));
        }
        catch (OperatorException e)
        {
            throw new CRMFException("cannot wrap key: " + e.getMessage(), e);
        }

        AlgorithmIdentifier keyAlg = wrapper.getAlgorithmIdentifier();
        ASN1OctetString valueHint = null;
        DERBitString encValue = new DERBitString(bOut.toByteArray());

        return new EncryptedValue(intendedAlg, symmAlg, encSymmKey, keyAlg, valueHint, encValue);
    }
}
