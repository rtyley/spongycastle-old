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
import org.bouncycastle.util.Strings;

public class EncryptedValueBuilder
{
    private KeyWrapper wrapper;
    private OutputEncryptor encryptor;
    private EncryptedValuePadder padder;

    public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor)
    {
        this(wrapper, encryptor, null);
    }

    /**
     * Generate fixed length blocks masked using a seed of length seedLength.
     *
     * @param wrapper
     * @param encryptor
     * @param padder
     */
    public EncryptedValueBuilder(KeyWrapper wrapper, OutputEncryptor encryptor, EncryptedValuePadder padder)
    {
        this.wrapper = wrapper;
        this.encryptor = encryptor;
        this.padder = padder;
    }

    public EncryptedValue build(char[] revocationPassphrase)
        throws CRMFException
    {
        return encryptData(padData(Strings.toUTF8ByteArray(revocationPassphrase)));
    }

    public EncryptedValue build(X509CertificateHolder holder)
        throws CRMFException
    {
        try
        {
            return encryptData(padData(holder.getEncoded()));
        }
        catch (IOException e)
        {
            throw new CRMFException("cannot encode certificate: " + e.getMessage(), e);
        }
    }

    private EncryptedValue encryptData(byte[] data)
       throws CRMFException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        OutputStream eOut = encryptor.getOutputStream(bOut);

        try
        {
            eOut.write(data);

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
            wrapper.generateWrappedKey(encryptor.getKey());
            encSymmKey = new DERBitString(wrapper.generateWrappedKey(encryptor.getKey()));
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

    private byte[] padData(byte[] data)
    {
        if (padder != null)
        {
            return padder.getPaddedData(data);
        }

        return data;
    }
}
