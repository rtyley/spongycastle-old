package org.bouncycastle.cert.crmf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

public class EncryptedValueParser
{
    private EncryptedValue value;
    private EncryptedValuePadder padder;

    public EncryptedValueParser(EncryptedValue value)
    {
        this.value = value;
    }

    public EncryptedValueParser(EncryptedValue value, EncryptedValuePadder padder)
    {
        this.value = value;
        this.padder = padder;
    }

    private byte[] decryptValue(ValueDecryptorGenerator decGen)
        throws CRMFException
    {
        if (value.getIntendedAlg() != null)
        {
            throw new UnsupportedOperationException();
        }
        if (value.getValueHint() != null)
        {
            throw new UnsupportedOperationException();
        }

        InputDecryptor decryptor = decGen.getValueDecryptor(value.getKeyAlg(),
            value.getSymmAlg(), value.getEncSymmKey().getBytes());
        InputStream dataIn = decryptor.getInputStream(new ByteArrayInputStream(
            value.getEncValue().getBytes()));
        try
        {
            byte[] data = Streams.readAll(dataIn);

            if (padder != null)
            {
                return padder.getUnpaddedData(data);
            }
            
            return data;
        }
        catch (IOException e)
        {
            throw new CRMFException("Cannot parse decrypted data: " + e.getMessage(), e);
        }
    }

    public X509CertificateHolder readCertificateHolder(ValueDecryptorGenerator decGen)
        throws CRMFException
    {
        return new X509CertificateHolder(X509CertificateStructure.getInstance(decryptValue(decGen)));
    }

    public char[] readRevocationPassphrase(ValueDecryptorGenerator decGen)
        throws CRMFException
    {
        return Strings.fromUTF8ByteArray(decryptValue(decGen)).toCharArray();
    }
}
