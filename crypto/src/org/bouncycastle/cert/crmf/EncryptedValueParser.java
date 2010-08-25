package org.bouncycastle.cert.crmf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.asn1.crmf.EncryptedValue;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.InputDecryptor;
import org.bouncycastle.util.io.Streams;

public class EncryptedValueParser
{
    private EncryptedValue value;

    public EncryptedValueParser(EncryptedValue value)
    {
        this.value = value;
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
            return Streams.readAll(dataIn);
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
}
